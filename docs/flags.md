# Флаги

## Клиент

| Флаг | По умолчанию | Описание |
| --- | --- | --- |
| `-listen` | `127.0.0.1:9000` | локальный адрес `ip:port`, куда подключается WireGuard или Xray клиент |
| `-peer` | **обязательный** | адрес сервера на VPS, `host:port` |
| `-provider` | `vk` | источник TURN-creds: `vk` (см. `docs/providers.md`) |
| `-link` | пусто | (устарел) одна ссылка VK Calls `https://vk.ru/call/join/...`; используйте `-links`. Игнорируется, если задан `-links` |
| `-links` | **обязательный для `-provider vk`** (или `-link`) | ссылки VK Calls через запятую `https://vk.ru/call/join/A,https://vk.ru/call/join/B`; каждая даёт свой пул из `-n` стримов |
| `-n` | `10` | параллельных TURN-потоков |
| `-transport` | `tcp` | транспорт до TURN-реле: `tcp` (TCP/TLS) \| `udp` |
| `-mode` | `udp` | режим туннеля: `udp` (UDP-релей для WireGuard) \| `tcp` (TCP-форвардер для Xray/sing-box) |
| `-bond` | `false` | распределять одно TCP-соединение по всем активным smux-сессиям (только с `-mode tcp`) |
| `-turn` | из creds | переопределить IP TURN-сервера |
| `-port` | из creds | переопределить порт TURN-сервера |
| `-obf-profile` | `none` | wire-профиль обфускации payload: `none` \| `rtpopus` (RTP/opus + ChaCha20-Poly1305 AEAD) \| `rtpopus2` (+ RTP header extension, ближе к WebRTC) \| `rtpopus3` (+ abs-send-time, VAD, имитация потерь, вариативный timestamp); должен совпадать с сервером |
| `-obf-key` | пусто | общий ключ для `-obf-profile != none`, 32 байта hex (64 символа) |
| `-obf-timing` | `0` | межпакетная задержка для RTP-мимикрии (напр. `20ms`); только с `-obf-profile != none` и `-mode udp`; `0` = выкл |
| `-gen-obf-key` | `false` | напечатать новый ключ и выйти |
| `-manual-captcha` | `false` | сразу ручной режим captcha (только `-provider vk`) |
| `-streams-per-cred` | `10` | потоков на один кеш VK-учёток (только `-provider vk`) |
| `-browser` | `firefox` | браузерный профиль VK-auth (UA + TLS JA3 + client hints): `chrome` \| `firefox` (только `-provider vk`) |
| `-dns-mode` | `auto` | `plain` (UDP/53) \| `doh` \| `auto` |
| `-dns-servers` | пусто | свои UDP/53 резолверы, `ip[:port][,ip[:port]...]` |
| `-client-id` | авто | уникальный ID клиента (автогенерация если не задан) |
| `-sub` | пусто | URL подписки (sub.md) для получения списка серверов |
| `-debug` | `false` | debug-логи |

## Сервер

| Флаг | По умолчанию | Описание |
| --- | --- | --- |
| `-config` | пусто | путь к JSON-файлу конфигурации; при указании остальные флаги игнорируются |
| `-listen` | `0.0.0.0:56000` | адрес прослушивания `ip:port` |
| `-connect` | **обязательный** | локальный backend `host:port` (WG `127.0.0.1:51820` / Xray `127.0.0.1:443`) |
| `-mode` | `udp` | режим туннеля: `udp` \| `tcp` (bond автоопределяется) |
| `-obf-profile` | `none` | wire-профиль обфускации payload: `none` \| `rtpopus` \| `rtpopus2` \| `rtpopus3`; должен совпадать с клиентом (описание профилей - в таблице клиента) |
| `-obf-timing` | `0` | межпакетная задержка для RTP-мимикрии (напр. `10ms`); только с `-obf-profile != none` и `-mode udp`; `0` = выкл |
| `-obf-key` | пусто | общий ключ для `-obf-profile != none`, 32 байта hex |
| `-gen-obf-key` | `false` | напечатать новый ключ и выйти |
| `-clients-file` | пусто | путь к JSON-файлу (`clients.json`) для включения авторизации по Client ID |
| `-debug` | `false` | debug-логи |

### Конфигурационный файл (`-config`)

Флаг `-config` позволяет задать настройки сервера через JSON-файл. При его указании все остальные флаги командной строки игнорируются, а Authorized Client ID хранятся внутри того же файла (ключ `clients`).

```json
{
  "connect":     "127.0.0.1:51820",
  "listen":      "0.0.0.0:56000",
  "mode":        "udp",
  "obf_profile": "none",
  "obf_key":     "",
  "obf_timing":  "0",
  "debug":       false,
  "clients": {
    "client-id-1": {
      "comment": "описание",
      "wg_pub_key": "…",
      "wg_address": "10.13.13.2",
      "wg_config": "[Interface]\nPrivateKey = …\n..."
    },
    "client-id-2": { "comment": "ещё один" }
  }
}
```

> **Дисклеймер:** поля, не указанные в JSON-файле, получают значения по умолчанию — те же, что и у соответствующих CLI-флагов (см. таблицу сервера). Исключение: `connect` — обязателен всегда. В режиме `-config` клиенты всегда сохраняются внутрь конфига; флаг `-clients-file` игнорируется.

## Управление Client ID (Команды Сервера)

> [!NOTE]
> **Про авторизацию:** клиент **всегда** отправляет свой Client ID первой записью после DTLS-handshake, сервер **всегда** его читает — wire-контракт симметричен. Авторизация включается указанием файла с allowlist. Если сервер запущен с `-config`, клиенты хранятся внутри самого конфига (ключ `clients`). Если без `-config` — используется отдельный файл, заданный через `-clients-file` или переменную окружения `CLIENTS_FILE`. Без allowlist ID читается и игнорируется.

Сервер содержит встроенные команды для управления allowlist (горячая перезагрузка поддерживается автоматически, перезапускать сервер после изменений не нужно).

```bash
# С отдельным файлом clients.json
./server clients add <client_id> ["Комментарий"]

# С единым конфигом (-config)
./server -config /etc/server.json clients add <client_id> ["Комментарий"]

# Удалить клиента
./server clients remove|del <client_id>

# Вывести список всех клиентов
./server clients list

# Показать freeturn:// ссылку и QR-код для конкретного клиента
./server clients show <client_id>
```

> **При добавлении клиента** (`clients add`) сервер автоматически:
> 1. Генерирует WireGuard-ключи для этого клиента
> 2. Добавляет пира в `/etc/wireguard/wg0.conf` (с назначением IP из пула `10.13.13.x`)
> 3. Применяет изменения в рантайме через `wg set` — **перезапускать WireGuard не нужно**
> 4. Генерирует персональный WireGuard-конфиг для клиента и встраивает его в `freeturn://` ссылку
> 5. Выводит `freeturn://` URI и QR-код для передачи клиенту
>
> Если `wg` не установлен или конфиг WireGuard не найден, пир не создаётся — клиент всё равно добавляется в allowlist (но без WG-конфига в ссылке).
>
> **Важно:** команды `clients add/remove/del/show` работают с `wg` и файлами в `/etc/wireguard/`, поэтому требуют прав root. Т.е systemd юнит сервера должен работать под тем же пользователем, что и wireguard. Если сервер запущен в Docker, команды нужно выполнять **на хосте** (не внутри контейнера), т.к. WireGuard живёт в ядре хоста и недоступен из контейнера.

Без флага `-config` команды по умолчанию работают с файлом `clients.json` в текущей директории. Если вы используете другой путь, задайте его через переменную окружения `CLIENTS_FILE`:
```bash
CLIENTS_FILE=/etc/free-turn-proxy/clients.json ./server clients list
```

### Управление через Docker

Если сервер запущен в Docker-контейнере (например, с именем `free-turn-proxy`), вы можете использовать команду `docker exec` для управления клиентами без необходимости заходить внутрь контейнера или редактировать файл вручную:

```bash
# Добавить клиента
docker exec -it free-turn-proxy /app/server clients add "my-client" "Комментарий"

# Удалить клиента
docker exec -it free-turn-proxy /app/server clients remove "my-client"

# Посмотреть список
docker exec -it free-turn-proxy /app/server clients list

# Показать ссылку и QR для существующего клиента
docker exec -it free-turn-proxy /app/server clients show "my-client"
```

> **Важно:** команды `docker exec` берут путь к файлу из переменной окружения `CLIENTS_FILE` контейнера. Это работает, только если контейнер запущен с включённой авторизацией (т.е. `CLIENTS_FILE` задан в `docker-compose.yml` и файл проброшен через `volumes`). Если авторизация выключена, `clients` пишет в эфемерный `clients.json` внутри контейнера, который сервер не читает. Путь должен совпадать с тем, что смонтирован и передан в `-clients-file`.

### Управление через systemd

Пример systemd-юнита (бинаррь по умолчанию в `/opt/free-turn-proxy/server`):

```ini
[Unit]
Description=Free TURN Proxy Server
After=network.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/opt/free-turn-proxy/server \
    --listen 0.0.0.0:56000 \
    --connect 127.0.0.1:51820 \
    --mode udp \
    --obf-profile rtpopus \
    --obf-key "..." \
    --clients-file /opt/free-turn-proxy/clients.json
Restart=always
RestartSec=5
User=nobody
Group=nogroup
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

Полный пример с комментариями: `docs/server.service.example`.

> **Важно:** сам сервер не требует root (порт 56000 непривилегированный), но CLI-команды `clients add/remove/del/show` — требуют, т.к. обращаются к `wg` и `/etc/wireguard/`. Запускайте их через `sudo`.

### WireGuard-интеграция

При добавлении клиента сервер автоматически создаёт WireGuard-пира. Поведение настраивается через переменные окружения:

| Переменная | По умолчанию | Описание |
| --- | --- | --- |
| `WG_CONFIG_PATH` | `/etc/wireguard/wg0.conf` | путь к конфигурации WireGuard-сервера |
| `WG_INTERFACE` | `wg0` | имя WireGuard-интерфейса |
| `WG_ENDPOINT` | `127.0.0.1:9000` | endpoint в клиентском WG-конфиге (адрес локального free-turn-proxy client) |
| `CLIENTS_FILE` | `clients.json` | путь к файлу clients.json для команд `server clients *` без `-config` |

WireGuard-пиры используют подсеть `10.13.13.x/24` (сервер — `.1`, клиенты — `.2`, `.3` и т.д.). При удалении клиента пир автоматически удаляется из конфига и рантайма.

## QR-код

При запуске сервер выводит QR-код с share link: `freeturn://`-ссылка для подключения (содержит настройки сервера, obf-ключ, client ID и WireGuard-конфиг). Сканируется [Android-приложением](https://github.com/netzgiest/turn-proxy-android) или аналогичного для быстрого импорта.

Формат: `freeturn://` + `base64url(JSON)`. JSON-схема:

| Поле | Описание |
| --- | --- |
| `v` | Версия формата (1) |
| `provider` | Провайдер TURN-учёток (`vk`) |
| `peer` | Адрес сервера `host:port` |
| `transport` | Транспорт до TURN (`tcp` / `udp`) |
| `mode` | Режим туннеля (`udp` / `tcp`) |
| `obf` | Профиль обфускации (если не `none`) |
| `key` | Obf-ключ hex (если obf != none) |
| `cid` | Client ID |
| `wg` | WireGuard-конфиг клиента (опционально) |
| `name` | Название сервера (опционально) |

