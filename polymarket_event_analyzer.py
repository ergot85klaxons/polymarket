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
TEST_TELEGRAM      = os.getenv("TEST_TELEGRAM", "0") == "1"      # послать тестовый пинг и проверить доставку
STATE_FILE         = os.getenv("STATE_FILE", "state.json")

WATCH_SLUGS      = [s.strip() for s in os.getenv("WATCH_SLUGS", "").split(",") if s.strip()]
WATCH_TOP_EVENTS = int(os.getenv("WATCH_TOP_EVENTS", "30"))
POLL_INTERVAL_S  = int(os.getenv("POLL_INTERVAL_S", "45"))
DISCOVERY_REFRESH_S = int(os.getenv("DISCOVERY_REFRESH_S", "1800"))
TRADES_LIMIT     = int(os.getenv("TRADES_LIMIT", "1000"))       # сколько сделок тянуть на рынок

# Фильтр мусорных рынков и потолок ------------------------------------------ #
MIN_MARKET_VOL24 = float(os.getenv("MIN_MARKET_VOL24", "5000"))  # мин. суточный объём рынка, $
REQUIRE_ORDERBOOK = os.getenv("REQUIRE_ORDERBOOK", "1") == "1"   # только рынки с активным ордербуком
MAX_MARKETS      = int(os.getenv("MAX_MARKETS", "400"))          # жёсткий потолок числа рынков (0 = без лимита)

# Адаптивный темп запросов -------------------------------------------------- #
REQ_INTERVAL_MIN = float(os.getenv("REQ_INTERVAL_MIN", "0.15"))  # базовая пауза между запросами, сек
REQ_INTERVAL_MAX = float(os.getenv("REQ_INTERVAL_MAX", "3.0"))   # макс. пауза при троттлинге

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
PRICE_MIN      = float(os.getenv("PRICE_MIN", "0.02"))         # ниже = пыль/лотерейный шум, игнор
PRICE_MAX      = float(os.getenv("PRICE_MAX", "0.70"))         # выше = слишком дорого, апсайд мал — не инсайд
ACCUMULATION_ONLY = os.getenv("ACCUMULATION_ONLY", "1") == "1"  # считать только набор позиции (net>0), отток игнор
W_LONGSHOT     = float(os.getenv("W_LONGSHOT", "1.5"))         # вес бонуса за дешевизну исхода
MIN_VOL_SHARE  = float(os.getenv("MIN_VOL_SHARE", "0.01"))     # мин. доля нетто-потока в суточном объёме рынка (1%)
W_VOLSHARE     = float(os.getenv("W_VOLSHARE", "0.5"))         # вес множителя за долю в объёме
WINDOW_BINS    = int(os.getenv("WINDOW_BINS", "3"))            # сколько бинов = "текущее окно" накопления (3*BIN_SEC)
MIN_SURGE      = float(os.getenv("MIN_SURGE", "2.0"))          # мин. всплеск объёма окна над его нормой (×)
W_SURGE        = float(os.getenv("W_SURGE", "0.6"))            # вес множителя за всплеск объёма

W_FRAG, W_COORD, W_PERSIST, W_FVP = 0.6, 0.8, 0.4, 0.3
W_CONC            = float(os.getenv("W_CONC", "1.2"))          # вес концентрации притока в один исход события
MIN_EVENT_MARKETS = int(os.getenv("MIN_EVENT_MARKETS", "3"))   # с какого числа кандидатов события считать концентрацию

GAMMA = "https://gamma-api.polymarket.com"
DATA  = "https://data-api.polymarket.com"

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s | %(levelname)s | %(message)s",
                    datefmt="%H:%M:%S")
log = logging.getLogger("pm-event")

SESSION = requests.Session()
SESSION.headers.update({"Accept": "application/json", "User-Agent": "pm-event-analyzer/1.1"})


class Pacer:
    """Глобальный темп запросов: замедляется при 429, плавно разгоняется обратно."""
    def __init__(self, base, mx):
        self.base = self.interval = base
        self.max = mx
        self.last = 0.0

    def wait(self):
        delta = time.monotonic() - self.last
        if delta < self.interval:
            time.sleep(self.interval - delta)
        self.last = time.monotonic()

    def throttled(self):
        self.interval = min(self.interval * 2, self.max)
        log.warning("Троттлинг: пауза между запросами повышена до %.2fs", self.interval)

    def ok(self):
        self.interval = max(self.base, self.interval * 0.9)


PACER = Pacer(REQ_INTERVAL_MIN, REQ_INTERVAL_MAX)


def _get(url, params=None, retries=3, timeout=15):
    for attempt in range(retries):
        PACER.wait()
        try:
            r = SESSION.get(url, params=params, timeout=timeout)
            if r.status_code == 429:
                PACER.throttled()
                time.sleep(2 ** attempt); continue
            r.raise_for_status()
            PACER.ok()
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

    def _ingest_event(self, ev, forced=False):
        """forced=True (рынки из WATCH_SLUGS) — добавляем без фильтра по объёму."""
        ev_slug = ev.get("slug")
        title_ev = ev.get("title") or ev_slug
        for m in ev.get("markets", []):
            cid = m.get("conditionId")
            if not cid:
                continue

            # --- фильтр мусора (кроме явно запрошенных через WATCH_SLUGS) ---
            vol24 = float(m.get("volume24hr") or m.get("volumeNum") or 0)
            if not forced:
                if m.get("closed") or m.get("active") is False:
                    continue
                if REQUIRE_ORDERBOOK and not m.get("enableOrderBook", True):
                    continue
                if vol24 < MIN_MARKET_VOL24:
                    continue

            # --- названия исходов: поддержка двух форматов Gamma ---
            tokens = {}
            toks = m.get("tokens")
            if isinstance(toks, list) and toks:
                for t in toks:
                    if t.get("token_id"):
                        tokens[str(t["token_id"])] = t.get("outcome", "?")
            else:
                ids, outs = m.get("clobTokenIds"), m.get("outcomes")
                try:
                    ids = json.loads(ids) if isinstance(ids, str) else (ids or [])
                    outs = json.loads(outs) if isinstance(outs, str) else (outs or [])
                except (ValueError, TypeError):
                    ids, outs = [], []
                for i, tid in enumerate(ids):
                    tokens[str(tid)] = outs[i] if i < len(outs) else "?"

            self.markets[cid] = {
                "title": m.get("question") or title_ev,
                "event_slug": ev_slug,
                "tokens": tokens,
                "vol24": vol24,
            }

    def refresh(self):
        self.markets = {}
        for slug in WATCH_SLUGS:
            for ev in (_get(f"{GAMMA}/events", params={"slug": slug}) or []):
                self._ingest_event(ev, forced=True)
        for ev in (_get(f"{GAMMA}/events", params={
            "active": "true", "closed": "false",
            "order": "volume_24hr", "ascending": "false",
            "limit": WATCH_TOP_EVENTS,
        }) or []):
            self._ingest_event(ev)

        # потолок: при превышении оставляем самые объёмные рынки
        if MAX_MARKETS and len(self.markets) > MAX_MARKETS:
            top = sorted(self.markets.items(), key=lambda kv: -kv[1]["vol24"])[:MAX_MARKETS]
            self.markets = dict(top)

        self._last_discovery = time.time()
        log.info("Watchlist: %s рынков (фильтр: vol24h>=$%.0f, ордербук=%s)",
                 len(self.markets), MIN_MARKET_VOL24, REQUIRE_ORDERBOOK)

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

    @staticmethod
    def merge(bins):
        """Сливает список бинов в один агрегат-окно (по возрастанию времени)."""
        w = Bin()
        for b in bins:
            w.net += b.net
            w.gross += b.gross
            w.count += b.count
            w.sum_size += b.sum_size
            for k, v in b.wallet_net.items():
                w.wallet_net[k] += v
            if b.first_ts is not None and (w.first_ts is None or b.first_ts < w.first_ts):
                w.first_ts, w.first_price = b.first_ts, b.first_price
            if b.last_ts is not None and (w.last_ts is None or b.last_ts >= w.last_ts):
                w.last_ts, w.last_price = b.last_ts, b.last_price
        return w


# --------------------------------------------------------------------------- #
#  Анализатор
# --------------------------------------------------------------------------- #
class EventAnalyzer:
    def __init__(self):
        self.bins = defaultdict(OrderedDict)   # (cid, asset) -> {bin_idx: Bin}
        self._win_cache = {}                   # (cid,asset) -> window net, сбрасывается каждый цикл

    def reset_cycle_cache(self):
        self._win_cache = {}

    def window_net(self, cid, asset):
        """Нетто-поток текущего окна (последние WINDOW_BINS бинов) с кешем на цикл."""
        key = (cid, asset)
        if key in self._win_cache:
            return self._win_cache[key]
        series = self.bins.get(key)
        val = 0.0
        if series and len(series) >= WINDOW_BINS:
            idxs = sorted(series.keys())
            val = Bin.merge([series[i] for i in idxs[-WINDOW_BINS:]]).net
        self._win_cache[key] = val
        return val

    def event_concentration(self, cid, asset, pm, target_net):
        """Доля притока окна, приходящаяся на целевой исход, среди всех исходов события.
        Возвращает (concentration 0..1, число рынков-кандидатов события с потоком)."""
        ev = (pm.markets.get(cid) or {}).get("event_slug")
        if not ev:
            return 0.0, 0
        total = 0.0
        markets = set()
        for (cid2, asset2) in list(self.bins.keys()):
            if (pm.markets.get(cid2) or {}).get("event_slug") != ev:
                continue
            wn = abs(self.window_net(cid2, asset2))
            if wn > 0:
                total += wn
                markets.add(cid2)
        conc = (abs(target_net) / total) if total > 0 else 0.0
        return conc, len(markets)

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
        # нужно достаточно бинов, чтобы по базлайну набралось >= MIN_BASELINE скользящих окон
        if not series or len(series) < MIN_BASELINE + 2 * WINDOW_BINS - 1:
            return None
        idxs = sorted(series.keys())
        cur_bins = [series[i] for i in idxs[-WINDOW_BINS:]]      # текущее окно накопления
        base_bins = [series[i] for i in idxs[:-WINDOW_BINS]]     # история до окна
        cur = Bin.merge(cur_bins)                               # агрегат окна

        net = cur.net
        if abs(net) < MIN_NET_USD:
            return None
        if ACCUMULATION_ONLY and net <= 0:
            return None     # отток/сброс — чаще хедж или ребаланс, не инсайд

        # доля нетто-потока в суточном объёме рынка — "мелкий поток в большом волюме" отсекаем
        vol24 = float((pm.markets.get(cid) or {}).get("vol24", 0) or 0)
        vol_share = (abs(net) / vol24) if vol24 > 0 else 0.0
        if vol24 > 0 and vol_share < MIN_VOL_SHARE:
            return None

        # цена входа (объёмно-взвешенная) — инсайд интересен только в "живом" окне цен
        avg_price = (cur.gross / cur.sum_size) if cur.sum_size else 0.0
        if not (PRICE_MIN <= avg_price <= PRICE_MAX):
            return None

        # % прироста к объёму: объём окна против его же нормы (медиана по базлайну × длину окна)
        base_gross_per_bin = statistics.median([b.gross for b in base_bins]) if base_bins else 0.0
        expected_window_gross = base_gross_per_bin * WINDOW_BINS
        surge = (cur.gross / expected_window_gross) if expected_window_gross > 0 else (
            999.0 if cur.gross > 0 else 0.0)   # объём из ниоткуда на мёртвом рынке = большой всплеск
        if surge < MIN_SURGE:
            return None     # объём не подскочил относительно нормы — не накопление

        directionality = cur.directionality

        # z-score: окно против предыдущих окон такого же размера (скользящих, для статистики)
        base_window_nets = [abs(Bin.merge(base_bins[i:i + WINDOW_BINS]).net)
                            for i in range(len(base_bins) - WINDOW_BINS + 1)]
        z = modified_zscore(abs(net), base_window_nets, floor=MAD_FLOOR_USD)

        # --- ГЕЙТ ---
        if directionality < DIR_MIN or z < Z_MIN:
            return None
        base = z * directionality

        # longshot-бонус: чем дешевле исход, тем сильнее асимметрия знания
        longshot = max(0.0, min((PRICE_MAX - avg_price) / (PRICE_MAX - PRICE_MIN), 1.0))

        # fragmentation: число сделок окна против нормы по бинам
        hist_counts = [b.count for b in base_bins]
        hist_msize = [b.mean_size for b in base_bins if b.count]
        frag = 0.0
        if hist_counts and hist_msize:
            count_z = modified_zscore(cur.count / WINDOW_BINS, hist_counts, floor=2.0)
            if count_z >= 2.0 and cur.mean_size < 0.6 * statistics.median(hist_msize):
                frag = min(count_z / 2.0, 2.0)

        # coordination — свежесть кошельков всего окна (ленивый /activity)
        sign = 1 if net > 0 else -1
        contributors = sorted(cur.wallet_net.items(), key=lambda kv: -abs(kv[1]))[:MAX_FRESH_LOOKUPS]
        fresh_same_dir, n_fresh = 0.0, 0
        for w, wnet in contributors:
            if (1 if wnet > 0 else -1) == sign and pm.is_fresh(w, wallet_cache):
                fresh_same_dir += abs(wnet)
                n_fresh += 1
        coord = min(fresh_same_dir / abs(net), 1.0) if net else 0.0

        # persistence — сколько бинов подряд (внутри и до окна) держат знак нетто
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

        # flow-vs-price по всему окну
        fvp, fvp_label = 0.0, ""
        if cur.first_price and cur.last_price:
            dp = cur.last_price - cur.first_price
            if dp * net > 0 and abs(dp) > 0.01:
                fvp, fvp_label = 1.0, "цена подтверждает (агрессивная переоценка)"
            elif abs(dp) < 0.005:
                fvp, fvp_label = 0.7, "стелс-накопление (цена ещё не двинулась)"

        volshare_norm = min(vol_share / MIN_VOL_SHARE, 3.0) if vol_share else 0.0
        surge_norm = min(surge / MIN_SURGE, 3.0)

        # концентрация: какую долю притока ВСЕГО события забирает этот исход
        conc, n_ev_markets = self.event_concentration(cid, asset, pm, net)
        conc_factor = conc if n_ev_markets >= MIN_EVENT_MARKETS else 0.0

        ifs = base * (1 + W_LONGSHOT * longshot + W_VOLSHARE * volshare_norm
                      + W_SURGE * surge_norm + W_CONC * conc_factor
                      + W_FRAG * frag + W_COORD * coord
                      + W_PERSIST * persist_norm + W_FVP * fvp)

        return {"ifs": ifs, "net": net, "directionality": directionality, "z": z,
                "frag": frag, "coord": coord, "n_fresh": n_fresh, "persist": persist,
                "fvp_label": fvp_label, "n_wallets": len(cur.wallet_net),
                "count": cur.count, "asset": asset, "longshot": longshot,
                "vol_share": vol_share, "vol24": vol24, "surge": surge,
                "conc": conc, "n_ev_markets": n_ev_markets,
                "avg_price": avg_price,
                "first_price": cur.first_price or 0.0,
                "last_price": cur.last_price or 0.0}


# --------------------------------------------------------------------------- #
#  Telegram
# --------------------------------------------------------------------------- #
def send_telegram(text):
    if DRY_RUN or not (TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID):
        log.info("[DRY_RUN/без токена]\n%s", text); return
    try:
        r = SESSION.post(f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage",
                         json={"chat_id": TELEGRAM_CHAT_ID, "text": text,
                               "parse_mode": "HTML", "disable_web_page_preview": False},
                         timeout=15)
        data = r.json()
        if not data.get("ok"):
            log.error("Telegram отклонил отправку: %s %s",
                      data.get("error_code"), data.get("description"))
        else:
            log.info("Telegram: сообщение отправлено")
    except (requests.RequestException, ValueError) as e:
        log.error("Telegram error: %s", e)


def build_alert(market, res):
    esc = html.escape
    title = esc(market["title"])
    outcome = esc(market["tokens"].get(res["asset"], res["asset"][:10] + "…"))
    side = "накопление" if res["net"] > 0 else "сброс"
    slug = market.get("event_slug") or ""

    # коэффициент: цена = вероятность исхода; десятичный кэф = 1/цена
    avg = res.get("avg_price") or 0.0
    fp, lp = res.get("first_price") or 0.0, res.get("last_price") or 0.0
    if avg > 0:
        odds = 1 / avg
        price_line = (f"коэффициент: <b>{avg*100:.1f}¢</b> (≈{avg*100:.0f}% вер., кэф {odds:.2f}×)"
                      f", бин {fp*100:.0f}→{lp*100:.0f}¢")
    else:
        price_line = "коэффициент: н/д"

    reasons = [
        f"чистый поток: <b>${res['net']:+,.0f}</b> ({side})",
        f"доля в объёме рынка: <b>{res.get('vol_share',0)*100:.1f}%</b> (vol24h ${res.get('vol24',0):,.0f})",
        f"всплеск объёма: <b>{res.get('surge',0):.1f}×</b> над нормой (окно {WINDOW_BINS*BIN_SEC//60} мин)",
        price_line,
        f"однонаправленность: {res['directionality']*100:.0f}%",
        f"аномальность z={res['z']:.1f}",
        f"кошельков в бине: {res['n_wallets']}, сделок: {res['count']}",
    ]
    if res.get("n_ev_markets", 0) >= MIN_EVENT_MARKETS and res.get("conc", 0) >= 0.5:
        reasons.append(f"⚠️ КОНЦЕНТРАЦИЯ В СОБЫТИИ: {res['conc']*100:.0f}% всего притока "
                       f"события (из {res['n_ev_markets']} кандидатов) — в этот исход")
    if res.get("longshot", 0) >= 0.6:
        reasons.append("⚠️ ЛОНГШОТ: крупный поток в дешёвый исход (высокая асимметрия)")
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
        # темп запросов держит глобальный PACER внутри _get

    now = time.time()
    an.reset_cycle_cache()   # окно-кеш строится заново на свежих данных цикла
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

    if TEST_TELEGRAM:
        log.info("TEST_TELEGRAM=1 -> шлю тестовый пинг в Telegram")
        send_telegram("✅ Тест связи: бот мониторинга Polymarket на связи. "
                      "Если ты это видишь — доставка в Telegram работает.")

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
