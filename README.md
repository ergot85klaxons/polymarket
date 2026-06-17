# Polymarket Insider-Flow Monitor (GitHub Actions)

Событийный детектор аномального потока ставок -> Telegram. Запускается раз в ~10 минут
на бесплатных GitHub Actions (одним проходом), без своего сервера.

## Настройка за 5 шагов

1. **Создай ПУБЛИЧНЫЙ репозиторий** и положи в него файлы:
   `polymarket_event_analyzer.py`, `requirements.txt`, `.github/workflows/monitor.yml`.
   (Публичный — потому что только у публичных репо Actions бесплатны без лимита минут.
   Секреты в коде не лежат, см. шаг 3.)

2. **Telegram-бот:** напиши @BotFather -> `/newbot` -> получи токен.
   Свой chat_id узнай у @userinfobot.

3. **Secrets:** Settings -> Secrets and variables -> Actions -> New repository secret:
   - `TELEGRAM_BOT_TOKEN`
   - `TELEGRAM_CHAT_ID`
   (Опц.) во вкладке *Variables* добавь `WATCH_SLUGS` — slug'и событий через запятую.

4. **Тест:** вкладка Actions -> workflow -> *Run workflow* (ручной запуск).
   Сначала можно раскомментировать `DRY_RUN: '1'` в monitor.yml — тогда алерты
   только в лог, без отправки в Telegram. Убедись, что проход проходит без ошибок.

5. **Готово.** Дальше cron запускает его сам каждые ~10 минут.

## Важные нюансы Actions

- Расписание cron может **задерживаться** в часы пик и иногда пропускать запуск —
  это near-realtime, не realtime.
- Scheduled-воркфлоу **отключается после ~60 дней без активности** в репо
  (сделай редкий коммит, чтобы держать живым).
- Приватный репо съест бесплатные 2000 мин/мес очень быстро при частом запуске —
  используй публичный, либо увеличь интервал, либо self-hosted runner.

## Тюнинг (env в monitor.yml)
`BIN_SEC` (держи = шагу cron), `DIR_MIN`, `Z_MIN`, `ALERT_IFS`, `MIN_NET_USD`,
`WATCH_TOP_EVENTS`, `TRADES_LIMIT`, `ALERT_COOLDOWN_S`.

## Альтернатива для настоящего realtime
Постоянно живущий процесс (Fly.io / Railway / Oracle Cloud Always Free VM / дешёвый VPS)
запускает тот же файл БЕЗ `RUN_ONCE` — тогда окно живёт в памяти и можно перейти
на WebSocket CLOB для near-instant сигналов.
