#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Polymarket Event-Level Insider-Flow Analyzer -> Telegram

Работает в двух режимах:
  • непрерывный цикл (локально / на сервере): держит окно в памяти;
  • RUN_ONCE=1 (для GitHub Actions / cron): один проход — пересобирает окно
    анализа из API, считает IFS, шлёт алерты, сохраняет state.json и выходит.

Устойчив к маскировке (см. методологию):
  • шум-ставки      -> NET signed flow (шум нетится), гейт по directionality
  • дробление       -> агрегация по бинам + подпись дробления (count↑ при size↓)
  • много кошельков -> агрегация на уровне ИСХОДА + coordination свежих адресов

IFS (через гейтинг):
  если directionality < DIR_MIN или robust_z < Z_MIN -> IFS ≈ 0
  иначе IFS = robust_z*directionality * (1 + frag + coord + persist + flow_vs_price)

ВАЖНО: детектор аномалий, не доказательство инсайда. Сигнал для проверки.
"""

import os
import json
import time
import html
import logging
import statistics
from collections import defaultdict, OrderedDict

import requests

# --------------------------------------------------------------------------- #
#  КОНФИГ
# --------------------------------------------------------------------------- #
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID   = os.getenv("TELEGRAM_CHAT_ID", "")
DRY_RUN            = os.getenv("DRY_RUN", "0") == "1"
RUN_ONCE           = os.getenv("RUN_ONCE", "0") == "1"          # один проход для cron/Actions
STATE_FILE         = os.getenv("STATE_FILE", "state.json")

WATCH_SLUGS      = [s.strip() for s in os.getenv("WATCH_SLUGS", "").split(",") if s.strip()]
WATCH_TOP_EVENTS = int(os.getenv("WATCH_TOP_EVENTS", "30"))
POLL_INTERVAL_S  = int(os.getenv("POLL_INTERVAL_S", "45"))
DISCOVERY_REFRESH_S = int(os.getenv("DISCOVERY_REFRESH_S", "1800"))
TRADES_LIMIT     = int(os.getenv("TRADES_LIMIT", "1000"))       # сколько сделок тянуть на рынок

# Бины и горизонт ----------------------------------------------------------- #
BIN_SEC        = int(os.getenv("BIN_SEC", "600"))    # размер бина (10 мин = шаг cron)
HORIZON_BINS   = int(os.getenv("HORIZON_BINS", "24"))
MIN_BASELINE   = int(os.getenv("MIN_BASELINE", "6"))

# Пороги/гейты -------------------------------------------------------------- #
DIR_MIN        = float(os.getenv("DIR_MIN", "0.55"))
Z_MIN          = float(os.getenv("Z_MIN", "3.0"))
MIN_NET_USD    = float(os.getenv("MIN_NET_USD", "1500"))
FRESH_WALLET_MAX = int(os.getenv("FRESH_WALLET_MAX", "15"))
ALERT_IFS      = float(os.getenv("ALERT_IFS", "6.0"))
ALERT_COOLDOWN_S = int(os.getenv("ALERT_COOLDOWN_S", "3600"))
MAX_FRESH_LOOKUPS = int(os.getenv("MAX_FRESH_LOOKUPS", "40"))   # лимит /activity-запросов на исход
MAD_FLOOR_USD  = float(os.getenv("MAD_FLOOR_USD", "500"))       # пол "шума" в $: ниже него разброс не считаем нулевым
Z_CAP          = float(os.getenv("Z_CAP", "10"))               # потолок z-score (защита от взрыва на тихих рынках)

W_FRAG, W_COORD, W_PERSIST, W_FVP = 0.6, 0.8, 0.4, 0.3

GAMMA = "https://gamma-api.polymarket.com"
DATA  = "https://data-api.polymarket.com"

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s | %(levelname)s | %(message)s",
                    datefmt="%H:%M:%S")
log = logging.getLogger("pm-event")

SESSION = requests.Session()
SESSION.headers.update({"Accept": "application/json", "User-Agent": "pm-event-analyzer/1.1"})


def _get(url, params=None, retries=3, timeout=15):
    for attempt in range(retries):
        try:
            r = SESSION.get(url, params=params, timeout=timeout)
            if r.status_code == 429:
                time.sleep(2 ** attempt); continue
            r.raise_for_status()
            return r.json()
        except requests.RequestException as e:
            log.warning("HTTP (%s/%s): %s", attempt + 1, retries, e)
            time.sleep(1 + attempt)
    return None


def modified_zscore(x, history, floor=0.0):
    """Robust z: 0.6745*(x-median)/MAD. floor — минимальный масштаб шума,
    чтобы при MAD≈0 (тихий рынок, одинаковые бины) не делить на ~0 и не получать
    бесконечный z. Результат ограничен ±Z_CAP."""
    if len(history) < MIN_BASELINE:
        return 0.0
    med = statistics.median(history)
    mad = statistics.median([abs(h - med) for h in history])
    scale = max(mad, floor)
    if scale <= 0:
        return 0.0                     # нет ни разброса, ни пола => оценить нельзя
    z = 0.6745 * (x - med) / scale
    return max(min(z, Z_CAP), -Z_CAP)


# --------------------------------------------------------------------------- #
#  Персистентность state.json (для RUN_ONCE)
# --------------------------------------------------------------------------- #
def load_state():
    try:
        with open(STATE_FILE, "r", encoding="utf-8") as f:
            s = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        s = {}
    return {
        "last_alert": {k: float(v) for k, v in s.get("last_alert", {}).items()},
        "wallet_cache": {k: v for k, v in s.get("wallet_cache", {}).items()},
    }


def save_state(state):
    # подрезаем кеш кошельков, чтобы файл не разрастался
    wc = state.get("wallet_cache", {})
    if len(wc) > 8000:
        state["wallet_cache"] = dict(list(wc.items())[-8000:])
    try:
        with open(STATE_FILE, "w", encoding="utf-8") as f:
            json.dump(state, f)
    except OSError as e:
        log.error("Не удалось сохранить state: %s", e)


# --------------------------------------------------------------------------- #
#  Клиент Polymarket
# --------------------------------------------------------------------------- #
class Polymarket:
    def __init__(self):
        self.markets = {}
        self._last_discovery = 0.0

    def _ingest_event(self, ev):
        ev_slug = ev.get("slug")
        title_ev = ev.get("title") or ev_slug
        for m in ev.get("markets", []):
            cid = m.get("conditionId")
            if not cid:
                continue
            tokens = {}
            for t in (m.get("tokens") or []):
                if t.get("token_id"):
                    tokens[str(t["token_id"])] = t.get("outcome", "?")
            self.markets[cid] = {
                "title": m.get("question") or title_ev,
                "event_slug": ev_slug,
                "tokens": tokens,
            }

    def refresh(self):
        for slug in WATCH_SLUGS:
            for ev in (_get(f"{GAMMA}/events", params={"slug": slug}) or []):
                self._ingest_event(ev)
        for ev in (_get(f"{GAMMA}/events", params={
            "active": "true", "closed": "false",
            "order": "volume_24hr", "ascending": "false",
            "limit": WATCH_TOP_EVENTS,
        }) or []):
            self._ingest_event(ev)
        self._last_discovery = time.time()
        log.info("Watchlist: %s рынков", len(self.markets))

    def maybe_refresh(self):
        if time.time() - self._last_discovery > DISCOVERY_REFRESH_S:
            self.refresh()

    def trades_for_market(self, cid, limit=None):
        return _get(f"{DATA}/trades", params={
            "market": cid, "takerOnly": "true", "limit": limit or TRADES_LIMIT,
        }) or []

    def is_fresh(self, address, wallet_cache):
        """True, если у кошелька мало истории сделок. Кеш живёт между запусками."""
        if not address:
            return False
        if address in wallet_cache:
            return wallet_cache[address] <= FRESH_WALLET_MAX
        acts = _get(f"{DATA}/activity",
                    params={"user": address, "type": "TRADE", "limit": FRESH_WALLET_MAX + 1})
        count = len(acts) if isinstance(acts, list) else FRESH_WALLET_MAX + 1
        wallet_cache[address] = count
        return count <= FRESH_WALLET_MAX


# --------------------------------------------------------------------------- #
#  Бин по одному исходу
# --------------------------------------------------------------------------- #
class Bin:
    __slots__ = ("net", "gross", "count", "sum_size",
                 "first_price", "last_price", "first_ts", "last_ts", "wallet_net")

    def __init__(self):
        self.net = 0.0
        self.gross = 0.0
        self.count = 0
        self.sum_size = 0.0
        self.first_price = self.last_price = None
        self.first_ts = self.last_ts = None
        self.wallet_net = defaultdict(float)   # wallet -> знаковый нетто (для coord)

    def add(self, side, price, size, ts, wallet):
        notional = price * size
        signed = notional if side == "BUY" else -notional
        self.net += signed
        self.gross += notional
        self.count += 1
        self.sum_size += size
        if self.first_ts is None or ts < self.first_ts:
            self.first_ts, self.first_price = ts, price
        if self.last_ts is None or ts >= self.last_ts:
            self.last_ts, self.last_price = ts, price
        if wallet:
            self.wallet_net[wallet] += signed

    @property
    def directionality(self):
        return abs(self.net) / self.gross if self.gross > 0 else 0.0

    @property
    def mean_size(self):
        return self.sum_size / self.count if self.count else 0.0


# --------------------------------------------------------------------------- #
#  Анализатор
# --------------------------------------------------------------------------- #
class EventAnalyzer:
    def __init__(self):
        self.bins = defaultdict(OrderedDict)   # (cid, asset) -> {bin_idx: Bin}

    def ingest(self, cid, trade):
        asset = str(trade.get("asset") or "")
        side = (trade.get("side") or "").upper()
        price = float(trade.get("price") or 0)
        size = float(trade.get("size") or 0)
        ts = int(trade.get("timestamp") or time.time())
        wallet = trade.get("proxyWallet") or trade.get("maker") or ""
        if not asset or price <= 0 or size <= 0 or side not in ("BUY", "SELL"):
            return
        bin_idx = ts // BIN_SEC
        series = self.bins[(cid, asset)]
        if bin_idx not in series:
            series[bin_idx] = Bin()
        series[bin_idx].add(side, price, size, ts, wallet)
        while len(series) > HORIZON_BINS:
            series.popitem(last=False)

    def analyze(self, cid, asset, pm, wallet_cache):
        series = self.bins.get((cid, asset))
        if not series or len(series) < MIN_BASELINE + 1:
            return None
        idxs = sorted(series.keys())
        cur = series[idxs[-1]]
        hist = [series[i] for i in idxs[:-1]]

        net = cur.net
        if abs(net) < MIN_NET_USD:
            return None
        directionality = cur.directionality
        z = modified_zscore(abs(net), [abs(b.net) for b in hist], floor=MAD_FLOOR_USD)

        # --- ГЕЙТ: дальше считаем тяжёлые метрики только если базовый сигнал есть ---
        if directionality < DIR_MIN or z < Z_MIN:
            return None
        base = z * directionality

        # (4) fragmentation
        hist_counts = [b.count for b in hist]
        hist_msize = [b.mean_size for b in hist if b.count]
        frag = 0.0
        if hist_counts and hist_msize:
            count_z = modified_zscore(cur.count, hist_counts, floor=2.0)
            if count_z >= 2.0 and cur.mean_size < 0.6 * statistics.median(hist_msize):
                frag = min(count_z / 2.0, 2.0)

        # (5) coordination — freshness ТОЛЬКО для кошельков текущего бина (ленивый /activity)
        sign = 1 if net > 0 else -1
        contributors = sorted(cur.wallet_net.items(), key=lambda kv: -abs(kv[1]))[:MAX_FRESH_LOOKUPS]
        fresh_same_dir = 0.0
        n_fresh = 0
        for w, wnet in contributors:
            if (1 if wnet > 0 else -1) == sign and pm.is_fresh(w, wallet_cache):
                fresh_same_dir += abs(wnet)
                n_fresh += 1
        coord = min(fresh_same_dir / abs(net), 1.0) if net else 0.0

        # (6) persistence
        persist = 0
        for i in reversed(idxs):
            b = series[i]
            if b.net == 0:
                continue
            if (1 if b.net > 0 else -1) == sign:
                persist += 1
            else:
                break
        persist_norm = min(persist / 4.0, 2.0)

        # (7) flow-vs-price
        fvp, fvp_label = 0.0, ""
        if cur.first_price and cur.last_price:
            dp = cur.last_price - cur.first_price
            if dp * net > 0 and abs(dp) > 0.01:
                fvp, fvp_label = 1.0, "цена подтверждает (агрессивная переоценка)"
            elif abs(dp) < 0.005:
                fvp, fvp_label = 0.7, "стелс-накопление (цена ещё не двинулась)"

        ifs = base * (1 + W_FRAG * frag + W_COORD * coord
                      + W_PERSIST * persist_norm + W_FVP * fvp)

        return {"ifs": ifs, "net": net, "directionality": directionality, "z": z,
                "frag": frag, "coord": coord, "n_fresh": n_fresh, "persist": persist,
                "fvp_label": fvp_label, "n_wallets": len(cur.wallet_net),
                "count": cur.count, "asset": asset}


# --------------------------------------------------------------------------- #
#  Telegram
# --------------------------------------------------------------------------- #
def send_telegram(text):
    if DRY_RUN or not (TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID):
        log.info("[DRY_RUN/без токена]\n%s", text); return
    try:
        SESSION.post(f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage",
                     json={"chat_id": TELEGRAM_CHAT_ID, "text": text,
                           "parse_mode": "HTML", "disable_web_page_preview": False},
                     timeout=15)
    except requests.RequestException as e:
        log.error("Telegram error: %s", e)


def build_alert(market, res):
    esc = html.escape
    title = esc(market["title"])
    outcome = esc(market["tokens"].get(res["asset"], res["asset"][:10] + "…"))
    side = "накопление" if res["net"] > 0 else "сброс"
    slug = market.get("event_slug") or ""
    reasons = [
        f"чистый поток: <b>${res['net']:+,.0f}</b> ({side})",
        f"однонаправленность: {res['directionality']*100:.0f}%",
        f"аномальность z={res['z']:.1f}",
        f"кошельков в бине: {res['n_wallets']}, сделок: {res['count']}",
    ]
    if res["frag"] > 0:
        reasons.append("⚠️ подпись ДРОБЛЕНИЯ (много мелких сделок)")
    if res["coord"] > 0.3:
        reasons.append(f"⚠️ КООРДИНАЦИЯ: {res['coord']*100:.0f}% потока от {res['n_fresh']} свежих кошельков")
    if res["persist"] >= 2:
        reasons.append(f"устойчивость: {res['persist']} бинов подряд в одну сторону")
    if res["fvp_label"]:
        reasons.append(res["fvp_label"])
    lines = [f"🎯 <b>Инсайдерский поток</b> | IFS={res['ifs']:.1f}",
             f"📊 <b>{title}</b>",
             f"➡️ исход: <b>{outcome}</b>", ""]
    lines += [f"• {r}" for r in reasons]
    if slug:
        lines += ["", f'🔗 <a href="https://polymarket.com/event/{esc(slug)}">Открыть рынок</a>']
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
#  Один проход анализа
# --------------------------------------------------------------------------- #
def trade_key(t):
    return f"{t.get('transactionHash','')}|{t.get('asset','')}|{t.get('proxyWallet','')}|{t.get('timestamp','')}"


def run_cycle(pm, an, state, seen):
    last_alert = state["last_alert"]
    wallet_cache = state["wallet_cache"]
    touched = set()

    for cid in list(pm.markets.keys()):
        for t in reversed(pm.trades_for_market(cid)):
            k = trade_key(t)
            if k in seen:
                continue
            seen[k] = True
            an.ingest(cid, t)
            asset = str(t.get("asset") or "")
            if asset:
                touched.add((cid, asset))
        time.sleep(0.2)   # бережём rate limit

    now = time.time()
    for (cid, asset) in touched:
        res = an.analyze(cid, asset, pm, wallet_cache)
        if not res or res["ifs"] < ALERT_IFS:
            continue
        if now - last_alert.get(f"{cid}|{asset}", 0) < ALERT_COOLDOWN_S:
            continue
        last_alert[f"{cid}|{asset}"] = now
        send_telegram(build_alert(pm.markets[cid], res))
        log.info("ALERT IFS=%.1f net=$%+.0f %s",
                 res["ifs"], res["net"], pm.markets[cid]["title"])
    log.info("Проход завершён. Рынков: %s, исходов проверено: %s", len(pm.markets), len(touched))


def main():
    pm = Polymarket()
    state = load_state()
    log.info("Старт. RUN_ONCE=%s DRY_RUN=%s бин=%ss порог IFS=%.1f",
             RUN_ONCE, DRY_RUN, BIN_SEC, ALERT_IFS)
    pm.refresh()

    if RUN_ONCE:
        an = EventAnalyzer()
        run_cycle(pm, an, state, seen={})
        save_state(state)
        return

    an = EventAnalyzer()
    seen = OrderedDict()
    while True:
        try:
            pm.maybe_refresh()
            run_cycle(pm, an, state, seen)
            if len(seen) > 100000:
                for _ in range(50000):
                    seen.popitem(last=False)
            save_state(state)
        except Exception as e:
            log.exception("Ошибка цикла: %s", e)
        time.sleep(POLL_INTERVAL_S)


if __name__ == "__main__":
    main()
