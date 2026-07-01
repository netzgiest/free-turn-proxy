# Providers

Источник TURN-реквизитов выбирается флагом `-provider` (default `vk`). Реализации удовлетворяют интерфейс `internal/provider.Provider` и подключаются в `cmd/client/main.go` через `buildProvider`.

## Доступные провайдеры

### `vk` (default)

VK Calls API. Перебирает встроенные `app_id/app_secret`, получает короткоживущие (≈10 мин) TURN-creds через 4-шаговый token chain. Solver captcha auto+manual.

**Обязательные флаги:**
- `-link` (устарел) или `-links` — VK callroom URL(ы) вида `https://vk.ru/call/join/<code>` (нормализуются до join-кода). `-links` поддерживает несколько URL через запятую.

**Несколько ссылок (`-links`):** каждая VK-ссылка даёт свой пул из `-n` TURN-потоков. Если передать N ссылок — клиент создаёт N независимых VK-провайдеров, объединённых в `multi.Provider`, который распределяет streamID по ним round-robin. Итоговое число стримов = `N * n`. Полезно для увеличения пропускной способности ценой нескольких звонков.

**Опциональные:**
- `-streams-per-cred` (default 10) — сколько TURN-стримов делят один кеш креденшалов.
- `-manual-captcha` — пропустить auto-solver, сразу открыть браузер.
- `-browser` — браузерный профиль HTTP-запросов control-plane к VK API: `chrome` | `firefox` (default). `firefox` несёт меньше client hints (sec-ch-ua\* — Chromium-only), что снижает fingerprint-поверхность. `chrome` даёт herd-cover, маскируясь под самый популярный браузер. Влияет на User-Agent, JA3-отпечаток TLS и заголовки client hints.