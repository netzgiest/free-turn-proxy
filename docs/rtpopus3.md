# RTPopus3 — продвинутый wire-профиль обфускации

## Обзор

`rtpopus3` — третий wire-профиль обфускации TURN-payload в Free Turn Proxy. Реализует глубокую мимикрию под реальный WebRTC-медиатрафик: голосовой RTP (Opus) с Video Frame Marking и периодическими видео-всплесками VP8.

Код: `internal/wire/rtpopus3/`

## Эволюция профилей

| Профиль | Отличия | HeaderLen | Overhead |
|---------|---------|-----------|----------|
| `rtpopus` (v1) | Базовый RTP-заголовок (12B) + nonce (12B) = 24B, X=0 | 24 | 40 |
| `rtpopus2` (v2) | + one-byte RTP extension (12B), X=1, audio-level + transport-cc | 36 | 52 |
| `rtpopus3` (v3) | + расширенный extension (20B): abs-send-time, MID, video-frame-marking, VAD, loss simulation, variable ts, CN/RED, multi-SSRC video | 44 | 60 |

## Wire-формат

```
[12B RTP hdr | 20B one-byte ext | 12B explicit nonce | AEAD ciphertext | 16B tag]
```

Общая длина: **HeaderLen=44, Overhead=60** байт.

### RTP Header (12B, RFC 3550)

```
byte 0:    0x90 | P-bit    V=2, P=0/1 (если padding), X=1, CC=0
byte 1:    M<<7 | PT       PT динамический: 111(opus)/13(CN)/127(RED)/96(VP8)
byte 2-3:  seq16 BE        монотонный с эмулируемыми пропусками (loss gaps)
byte 4-7:  ts32 BE         вариативный шаг 480/960/1920 (10/20/40ms)
byte 8-11: SSRC            случайный per-conn; для видео — отдельный SSRC
```

**P-bit** — выставляется в зависимости от VAD-фазы и типа пакета (подробнее ниже).

**PT (Payload Type)** — выбирается динамически:
- `0x6F` (111) — Opus audio (основной)
- `13` — Comfort Noise (CN, RFC 3389) во время silence
- `127` — RED (RFC 2198) для имитации FEC во время speech
- `96` — VP8 video (при видео-всплесках)

**Sequence** — монотонно возрастает, но с периодическими пропусками (gaps), эмулирующими потерю пакетов в сети. После gap seq увеличивается на `gapSize` (1-3).

**Timestamp** — шаг выбирается случайно с распределением:
- 480 (10ms @ 48kHz) — ~4%
- 960 (20ms @ 48kHz) — ~86% (основной)
- 1920 (40ms @ 48kHz) — ~10%

**SSRC**:
- для аудио — случайный per-connection
- для видео — отдельный случайный SSRC (multi-SSRC симуляция)

### RTP Extension (20B, RFC 8285 one-byte)

```
byte 12-13: 0xBE 0xDE                — профиль one-byte extension
byte 14-15: 0x0004                   — длина = 4 слова (16 байт данных)
```

Пять one-byte extension элементов:

| ID | Элемент | Байт | Размер данных | Описание |
|----|---------|------|---------------|----------|
| 1 | `ssrc-audio-level` | 16-17 | 1B | VAD-бит + уровень громкости (-dBov) |
| 2 | `transport-wide-cc` | 18-20 | 2B | Монотонный sequence для congestion control |
| 3 | `abs-send-time` | 21-24 | 3B | 24-bit NTP-таймстемп отправки (RFC 5285) |
| 4 | `MID` (RTP Stream ID) | 25-26 | 1B | `'a'` для audio, `'v'` для video |
| 5 | `video-frame-marking` | 27-28 | 1B | Флаги S/E/I + Temporal ID (T0-T2) |
| | padding | 29-31 | 3B | Выравнивание до 16 байт |

**audio-level** (байт 17): `0x80 | level` — MSB = VAD (1 = голос активен), остальные 7 бит — уровень в -dBov.

**abs-send-time** (байты 22-24): 24-битный NTP-таймстемп. Старшие 6 бит — секунды (mod 64), младшие 18 бит — дробная часть с разрешением ~3.8µs.

**video-frame-marking** (байт 28):
- `S` (bit 7) — начало видеокадра
- `E` (bit 6) — конец видеокадра
- `I` (bit 5) — ключевой кадр (IDR)
- `T2|T1|T0` (bits 2-0) — Temporal Layer ID

### Nonce (12B)

```
[4B sessionID | 8B counter (BE)]
```

- **sessionID** — 4 случайных байта; MSB кодирует направление: `0` = клиент→сервер, `1` = сервер→клиент.
- **counter** — 64-битный монотонный счётчик, стартует со случайного значения.

Nonce используется как IV для ChaCha20-Poly1305.

### AEAD

```
ChaCha20-Poly1305 (RFC 8439)
AAD = первые 44 байта (RTP hdr || extension || nonce)
```

Ключ — 32 байта, общий для клиента и сервера. Nonce-пространства разделены direction-bit в sessionID.

## Модель VAD (Voice Activity Detection)

VAD определяет, находится ли аудиопоток в фазе **speech** (разговор) или **silence** (молчание). Реализована как конечный автомат с Pareto-распределением длительности фаз.

### Параметры VAD

```
Speech (разговор):
  minPkts     = 30    — минимальная длительность (Pareto shift)
  shape       = 1.4   — Pareto alpha (тяжёлый хвост)

Silence (молчание):
  meanPkts    = 15    — средняя длительность (экспоненциальное)
  turnMean    = 75    — средняя для "смены говорящего" (экспоненциальное)
  turnChance  = 26/256 ≈ 10% — шанс смены говорящего
```

### Алгоритм работы VAD

1. При создании Conn аудио-состояние = `stateSpeech`.
2. Каждый пакет вызывает `updateAudioState()`:
   - Увеличивается счётчик `pktsInState`.
   - Если счётчик >= `nextStateSwitch`:
     - **Silence → Speech**: Pareto-длительность, устанавливается M=1 (маркер).
     - **Speech → Silence**: с шансом `turnChance` выбирается `turnMean` (имитация смены говорящего), иначе `meanPkts`; длительность по экспоненциальному распределению.
3. **Принудительный Speech**: если во время silence приходит трафик, VAD форсирует переход в speech (логика в `WrapInPlace`, строки 408-415).

### Воздействие VAD на трафик

| Характеристика | Speech | Silence |
|---------------|--------|---------|
| RTP Padding | 15% пакетов, 2-8 байт | 5% пакетов, 1-2 байта |
| Comfort Noise (PT=13) | — | 30% пакетов |
| RED (PT=127) | 15% пакетов, 2-6 байт | — |
| Audio level | 20-50 (-dBov) | 100-127 (-dBov) |
| Video bursts | Только во время speech | Подавлены (burst прерывается) |

## Loss Simulation (эмуляция потерь пакетов)

Для имитации сетевых потерь RTP sequence периодически содержит пропуски (gaps):

```
Параметры:
  gapInterval  = [50, 150] пакетов между gaps
  gapSize      = [1, 3] пропущенных пакета
```

Механизм: после `nextGapAt` пакетов `seq` увеличивается дополнительно на `gapSize`, создавая "потерю". На серверной стороне в `ReadFrom` (`listen.go:148-168`) отслеживаются пропуски seq и при разумном расхождении (diff 2..10) ставятся в очередь NACK RTCP-пакетов.

## RED-имитация FEC (PT=127)

Профиль эмулирует RED (Redundant Audio Data, RFC 2198) — 15% аудиопакетов во время speech маркируются PT=127 с RTP padding 2-6 байт. Это имитирует FEC-защиту реального WebRTC.

## Comfort Noise (PT=13)

Во время silence 30% пакетов маркируются PT=13 (Comfort Noise, RFC 3389). В реальном WebRTC CN-пакеты содержат параметры шума; здесь они несут обычный зашифрованный payload с минимальным padding (1-2 байта) для сходства.

## Multi-SSRC Video Bursts (VP8)

Имитация видео-всплесков — ключевое отличие от rtpopus2.

### Механизм

```
Параметры burst:
  burstMin      = 50 пакетов    (Pareto shift)
  burstMax      = 200 пакетов
  burstShape    = 1.5           (Pareto alpha)

Параметры интервалов:
  intervalMin   = 6000 пакетов  (Pareto shift)
  intervalMax   = 60000 пакетов
  intervalShape = 1.4

Параметры пакетов:
  videoChance   = 85/256 ≈ 33% — доля пакетов burst'а, которые — видео
  videoPktMin   = 400 байт
  videoPktMax   = 900 байт
  lenPrefix     = 4 байта — префикс с реальной длиной payload
```

### Алгоритм

1. **Периодичность**: каждые `videoInterval` пакетов (случайно от 6k до 60k) начинается новый burst.
2. **Начало burst**:
   - Только во время speech (VAD).
   - Только если `pktsInState >= videoBurstSpeechMin` (30 pkt с начала speech).
   - Длительность burst: Pareto(50, 1.5), каппинг на 200.
3. **Пакеты внутри burst**:
   - ~33% маркируются как видео (PT=96, отдельный SSRC).
   - Видеопакет имеет 4B префикс с real_len + заполнение (filler) до 400-900 байт.
   - Остальные ~67% — обычные аудиопакеты.
4. **Видео-капсуляция**:
   - `plaintext` = `[4B real_len][original_payload][random_filler]`
   - После расшифровки сервер читает `real_len` и отбрасывает filler.

### Структура видео-пакета

```
[12B RTP hdr (PT=96, video SSRC) | 20B ext (MID='v') | 12B nonce |
 4B real_len | plaintext (original payload) | random filler | 16B tag]
```

- В extension устанавливается `MID='v'` и `video-frame-marking` (S/E/I-биты + Temporal ID).
- Начало/конец/ключевой кадр — случайное распределение.

### Прерывание burst

Если VAD переходит в silence, burst немедленно прерывается — остаток сбрасывается. Это соответствует реальному поведению: видео прерывается, когда говорящий замолкает.

## RTP Padding

Padding имитирует защиту от утечки размера пакета (как в реальном SRTP):

| Тип пакета | Шанс padding | Диапазон |
|------------|-------------|----------|
| Opus audio | 15% | 2-8 байт |
| CN (silence) | 5% | 1-2 байта |
| RED (FEC) | 100% | 2-6 байт |
| Video | 0% | — |

Pad-байты — случайные (crypto/rand), последний байт = длина padding (RFC 3550 §5.1).

## RTCP-инжекция

Сервер периодически инжектирует RTCP-пакеты в поток, не затрагивая OBF-обёртку (RTCP-пакеты не являются RTP и пропускаются в `ReadFrom` без распаковки).

### Receiver Report (RR) + NACK

В `listen.go:217-261` сервер формирует compound RTCP:
- **NACK** (Generic NACK, RFC 4585, PT=205, FMT=1): запрос на переотправку пакетов, seq которых были пропущены (на основе наблюдений за seq клиента).
- **RR** (Receiver Report, PT=201): статистика приёма (случайные fraction lost, jitter).
- Интервал: 1-5 секунд (случайный).

### Client-side RTCP Injector

Параллельно работает `rtcp.Injector` (`internal/wire/rtcp/injector.go`), обёрнутый поверх OBF-слоя в relay. Он:
- Парсит RTP-заголовки проходящих пакетов (SSRC, timestamp, счётчики).
- Каждые 0.5-5s инжектирует compound SR+SDES (75%) или RR+SDES (25%).
- SDES CNAME — случайная 12-символьная base64-строка (как в Chromium WebRTC).

## Packet Shaping (pacing)

Поверх rtpopus3 может работать `shape.WrapPacketListener` — межпакетная задержка, имитирующая реальный медиа-поток:
- **Uniform jitter**: ±10% от interval.
- **Gaussian jitter**: более естественное распределение.
- **Burst mode**: до 3 пакетов без задержки (mini-batch, как в WebRTC).

Параметр `-obf-timing` управляет pacing-ом. Рекомендуемое значение: 20ms (соответствует Opus-фрейму).

## Практика

### Wire-размеры

| Payload | Wire packet (без padding) | Максимум |
|---------|--------------------------|----------|
| 1000 байт | 1060 | ~1070+ |
| 1400 байт | 1460 | ~1470+ |
| MTU (1500) | 1560 | ~1570+ |

Рекомендуемый MTU в WireGuard: 1280-1400 (с учётом overhead).

### Отладка

`SetLogf(logf)` на `Conn` или `Listener` включает логгирование фаз VAD, видео-всплесков и RTCP. Пример:
```
[VAD] разговор (speech) на ~87 пакетов
[VIDEO] burst START — 125 пакетов, след. burst через ~12487 пакетов
[VIDEO] pkt seq=42 ssrc=abcdef01 payload=342 burst_rem=124
[VIDEO] burst END
[VAD] молчание (silence) на ~23 пакетов
[RTCP] send NACK seqs=[15 16]
[RTCP] send RR ssrc=12345678
```

### Безопасность

`rtpopus3` — **обфускация, а не шифрование защищённого канала**. DTLS внутри TURN уже обеспечивает конфиденциальность и целостность. Задача профиля — сделать трафик неотличимым от RTP/RTCP для DPI/шейпинга VK.

ChaCha20-Poly1305 здесь для:
1. Целостности wire-заголовка (nonce, AAD).
2. Защиты от тривиального активного прослушивания (пассивный наблюдатель не увидит исходный payload).
3. Предотвращения подмены пакетов (AEAD-аутентификация).

### Сравнение версий

| Характеристика | rtpopus | rtpopus2 | rtpopus3 |
|---------------|---------|----------|----------|
| RTP extension (X=1) | ✗ | ✓ (2 elem) | ✓ (5 elem) |
| VAD silence/speech | ✗ | ✗ | ✓ |
| Loss simulation | ✗ | ✗ | ✓ |
| Variable timestamp | ✗ | ✗ | ✓ |
| Comfort Noise (PT=13) | ✗ | ✗ | ✓ |
| RED FEC (PT=127) | ✗ | ✗ | ✓ |
| Multi-SSRC video | ✗ | ✗ | ✓ |
| RTCP injection | ✗ | ✗ | ✓ |
| Packet shaping | ✓ | ✓ | ✓ |
| HeaderLen | 24 | 36 | 44 |
| Overhead | 40 | 52 | 60 |
