// SPDX-License-Identifier: MIT

// Package rtpopus3 - wire-профиль обфускации с улучшенной RTP-мимикрией:
// три one-byte extension (audio-level, transport-wide-cc, abs-send-time),
// вариативный шаг timestamp, эмуляция потери пакетов (gaps в seq),
// VAD-модель с переключением silence/speech, эмуляция RTP padding.
//
// Wire-формат (HeaderLen=40, Overhead=56):
//
//	[12B RTP hdr | 16B one-byte ext | 12B explicit nonce | AEAD ciphertext | 16B tag]
//
// RTP header (RFC 3550):
//
//	byte 0:    0x90|0x20   V=2, P=0/1 (padding ~10%), X=1, CC=0
//	byte 1:    M<<7 | 0x6F M=1 на старте talkspurt, PT=111 (opus)
//	byte 2-3:  seq16 BE    монотонный с пропусками (loss simulation)
//	byte 4-7:  ts32 BE     вариативный шаг 480/960/1920 (10/20/40ms)
//	byte 8-11: SSRC        полностью random per conn
//
// RTP extension (RFC 8285 one-byte, 12 байт данных -> 3 слова):
//
//	byte 12-13: 0xBE 0xDE      профиль one-byte
//	byte 14-15: 0x0003         длина = 3 слова (12 байт данных)
//	byte 16:    0x10           ssrc-audio-level: id=1, len=1
//	byte 17:    0x80|level     VAD + level (-dBov)
//	byte 18:    0x21           transport-wide-cc: id=2, len=2
//	byte 19-20: tccSeq16       монотонный transport-cc sequence
//	byte 21:    0x32           abs-send-time: id=3, len=2
//	byte 22-24: abs_send_time  24-bit NTP timestamp (mod 64s)
//	byte 25-27: 0x00           padding до 12 байт данных расширения
//
// 12B explicit nonce = 4B sessionID || 8B counter (BE). MSB sessionID
// кодирует направление. AAD = первые 40 байт (RTP hdr || ext || nonce).
//
// RTP padding (RFC 3550 §5.3.1): ~10% пакетов имеют P=1 и 1-4 байта padding
// в конце payload (до AEAD). Последний байт padding — длина padding'а.
// Приёмник читает P-бит, после AEAD-расшифровки отрезает padLen последних байт.
package rtpopus3

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	KeyLen    = 32
	rtpHdrLen = 12
	rtpExtLen = 16
	nonceLen  = 12
	tagLen    = 16
	headerLen = rtpHdrLen + rtpExtLen + nonceLen // 40
	overhead  = headerLen + tagLen               // 56
	rtpVerExt = 0x90                             // V=2, P=0, X=1, CC=0
	rtpPT     = 0x6F                             // M=0, PT=111 (opus)
	rtpMarker = 0x80                             // M=1

	rtpPaddingBit = 0x20 // P=1 в RTP header (byte 0, bit 5)

	paddingChance = 26 // 26/256 ≈ 10%
	paddingMin    = 1
	paddingMax    = 4

	extAudioLevelHdr  = 0x10 // id=1, len=1
	extTransportHdr   = 0x21 // id=2, len=2
	extAbsSendTimeHdr = 0x32 // id=3, len=2

	speechMinPkts     = 30  // минимум speech в пакетах (0.6s @ 50pps)
	speechShape       = 1.4 // α для Pareto-распределения speech
	silenceMeanPkts   = 15  // средняя micro-пауза (0.3s)
	silenceTurnMean   = 75  // средняя turn-taking пауза (1.5s)
	silenceTurnChance = 26  // 26/256 ≈ 10% шанс длинной паузы

	gapIntervalMin = 50
	gapIntervalMax = 150
	gapSizeMin     = 1
	gapSizeMax     = 3

	tsStep20ms = 960
	tsStep10ms = 480
	tsStep40ms = 1920

	// Multi-SSRC video simulation
	videoPT             = 96    // VP8 payload type
	videoBurstMin       = 50    // минимум пакетов в одной «вспышке» видео
	videoBurstMax       = 200   // максимум (кап после Pareto)
	videoBurstShape     = 1.5   // α для Pareto-распределения длины burst
	videoIntervalMin    = 6000  // минимум пакетов между вспышками
	videoIntervalMax    = 60000 // кап после Pareto (~2min при 50pps)
	videoIntervalShape  = 1.4   // α для Pareto-распределения интервала
	videoPktMinSize     = 400   // целевой размер видео-пакета (байт)
	videoPktMaxSize     = 900
	videoLenPrefix      = 4  // байт префикса с real_len перед payload
	videoBurstSpeechMin = 30 // сколько speech-пакетов должно пройти до burst
	videoChance         = 85 // 85/256 ≈ 33% — шанс что конкретный пакет в burst будет видео
)

func MaxWire(payloadLen int) int { return overhead + payloadLen + paddingMax + videoPktMaxSize }

type audioState int

const (
	stateSilence audioState = iota
	stateSpeech
)

type State struct {
	aead cipher.AEAD
}

// Logf — опциональный колбэк для отладочного логирования фаз VAD и видео.
type Logf func(format string, args ...any)

func NewState(key []byte) (*State, error) {
	if len(key) != KeyLen {
		return nil, fmt.Errorf("rtpopus3:key must be %d bytes (got %d)", KeyLen, len(key))
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, fmt.Errorf("rtpopus3:aead init: %w", err)
	}
	return &State{aead: aead}, nil
}

type Conn struct {
	state     *State
	sessionID [4]byte
	ssrc      [4]byte
	counter   atomic.Uint64
	seq       atomic.Uint32
	timestamp atomic.Uint32
	tcc       atomic.Uint32
	startTime time.Time

	audioState      audioState
	pktsInState     int
	nextStateSwitch int

	nextGapAt int
	gapSize   int

	// Multi-SSRC video simulation
	videoSSRC      [4]byte
	pktCounter     uint64
	nextVideoBurst uint64
	videoBurstRem  int
	videoInterval  int

	log Logf
}

func NewConn(key []byte, isServer bool) (*Conn, error) {
	s, err := NewState(key)
	if err != nil {
		return nil, err
	}
	return NewConnFromState(s, isServer)
}

func NewConnFromState(state *State, isServer bool) (*Conn, error) {
	if state == nil {
		return nil, errors.New("rtpopus3:nil state")
	}
	c := &Conn{
		state:           state,
		startTime:       time.Now(),
		audioState:      stateSpeech,
		nextStateSwitch: randPareto(speechMinPkts, speechShape),
		nextGapAt:       gapIntervalMin + randRange(gapIntervalMax-gapIntervalMin+1),
		gapSize:         gapSizeMin + randRange(gapSizeMax-gapSizeMin+1),
	}
	var rnd [16]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return nil, fmt.Errorf("rtpopus3:rand init: %w", err)
	}
	copy(c.sessionID[:], rnd[0:4])
	copy(c.ssrc[:], rnd[4:8])
	if isServer {
		c.sessionID[0] |= 0x80
	} else {
		c.sessionID[0] &^= 0x80
	}
	c.seq.Store(uint32(binary.BigEndian.Uint16(rnd[8:10])))
	c.timestamp.Store(binary.BigEndian.Uint32(rnd[10:14]))
	c.tcc.Store(uint32(binary.BigEndian.Uint16(rnd[14:16])))

	var cb [8]byte
	if _, err := rand.Read(cb[:]); err != nil {
		return nil, fmt.Errorf("rtpopus3:counter rand: %w", err)
	}
	c.counter.Store(binary.BigEndian.Uint64(cb[:]))

	var vrnd [4]byte
	if _, err := rand.Read(vrnd[:]); err != nil {
		return nil, fmt.Errorf("rtpopus3:video ssrc rand: %w", err)
	}
	copy(c.videoSSRC[:], vrnd[:])
	c.videoInterval = randPareto(videoIntervalMin, videoIntervalShape)
	if c.videoInterval > videoIntervalMax {
		c.videoInterval = videoIntervalMax
	}
	initialDelay := videoIntervalMin + randRange(2*videoIntervalMin)
	if initialDelay < 0 {
		initialDelay = 0
	}
	c.nextVideoBurst = uint64(initialDelay)

	return c, nil
}

func (*Conn) HeaderLen() int    { return headerLen }
func (*Conn) Overhead() int     { return overhead }
func (*Conn) MaxWire(n int) int { return MaxWire(n) }

// SetLogf устанавливает колбэк для отладочного логирования.
func (c *Conn) SetLogf(logf Logf) { c.log = logf }

func (c *Conn) SetVideoInterval(packets int) {
	if packets < 1 {
		packets = 6000
	}
	c.videoInterval = packets
	c.nextVideoBurst = c.pktCounter + uint64(packets)
}

func randRange(n int) int {
	if n <= 0 {
		return 0
	}
	var b [1]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("rtpopus3:rand: " + err.Error())
	}
	return int(b[0]) % n
}

// randFloat01 возвращает равномерное (0, 1] из crypto/rand.
func randFloat01() float64 {
	var b [7]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("rtpopus3:rand: " + err.Error())
	}
	v := uint64(b[0])<<48 | uint64(b[1])<<40 | uint64(b[2])<<32 |
		uint64(b[3])<<24 | uint64(b[4])<<16 | uint64(b[5])<<8 | uint64(b[6])
	return float64(v+1) / (float64(1<<56) + 1) // (0, 1]
}

// randPareto генерирует Pareto-распределение с shape α и минимумом shift.
// Используется для длительности речи (тяжёлый хвост).
func randPareto(shift int, alpha float64) int {
	u := randFloat01()
	return shift + int(float64(shift)*math.Pow(1-u, -1/alpha))
}

// randExponential генерирует экспоненциальное распределение с заданным mean.
// Используется для длительности пауз.
func randExponential(mean int) int {
	u := randFloat01()
	if u < 1e-15 {
		u = 1e-15
	}
	return int(-float64(mean) * math.Log(u))
}

func pickTsStep() uint32 {
	r := randRange(256)
	switch {
	case r < 10:
		return tsStep10ms
	case r < 230:
		return tsStep20ms
	default:
		return tsStep40ms
	}
}

func (c *Conn) updateAudioState() bool {
	c.pktsInState++
	if c.pktsInState < c.nextStateSwitch {
		return false
	}
	if c.audioState == stateSilence {
		c.audioState = stateSpeech
		c.nextStateSwitch = randPareto(speechMinPkts, speechShape)
		if c.log != nil {
			c.log("[VAD] разговор (speech) на ~%d пакетов", c.nextStateSwitch)
		}
		c.pktsInState = 0
		return true
	}
	var dur int
	if randRange(256) < silenceTurnChance {
		dur = randExponential(silenceTurnMean)
	} else {
		dur = randExponential(silenceMeanPkts)
	}
	c.audioState = stateSilence
	c.nextStateSwitch = dur
	if c.nextStateSwitch < 1 {
		c.nextStateSwitch = 1
	}
	if c.log != nil {
		c.log("[VAD] молчание (silence) на ~%d пакетов", c.nextStateSwitch)
	}
	c.pktsInState = 0
	return false
}

func (c *Conn) audioLevel() byte {
	if c.audioState == stateSpeech {
		return 0x80 | byte(20+randRange(31)) //nolint:gosec // bound: 20+[0,30] < 256
	}
	return byte(100 + randRange(28)) //nolint:gosec // bound: 100+[0,27] < 256
}

func (c *Conn) computeSeq() uint16 {
	seq := uint16(c.seq.Add(1) - 1) //nolint:gosec // RTP seq wraps at 16 bits
	c.nextGapAt--
	if c.nextGapAt > 0 {
		return seq
	}
	skip := uint32(c.gapSize) //nolint:gosec // gapSize ≤ 3
	c.seq.Add(skip)
	c.nextGapAt = gapIntervalMin + randRange(gapIntervalMax-gapIntervalMin+1)
	c.gapSize = gapSizeMin + randRange(gapSizeMax-gapSizeMin+1)
	return seq
}

func (c *Conn) absSendTime() uint32 {
	ms := time.Since(c.startTime).Milliseconds()
	if ms < 0 {
		ms = 0
	}
	sec := (ms / 1000) % 64
	frac := (ms % 1000) << 18 / 1000
	return uint32(sec)<<18 | uint32(frac)
}

func (c *Conn) WrapInto(dst, payload []byte) (int, error) {
	if len(dst) < c.MaxWire(len(payload)) {
		return 0, errors.New("rtpopus3:dst buffer too small")
	}
	copy(dst[headerLen:], payload)
	return c.WrapInPlace(dst, len(payload))
}

func (c *Conn) WrapInPlace(buf []byte, plainLen int) (int, error) {
	c.pktCounter++
	seq := c.computeSeq()

	// --- VAD state transition ---
	startedSpeech := c.updateAudioState()
	isSpeech := c.audioState == stateSpeech

	// Abort video burst early if user stopped talking
	if c.videoBurstRem > 0 && !isSpeech {
		if c.log != nil {
			c.log("[VIDEO] burst прерван — переход в молчание (оставалось %d)", c.videoBurstRem)
		}
		c.videoBurstRem = 0
	}

	// --- Start new video burst? (only during speech, not at very start) ---
	if c.videoBurstRem == 0 && isSpeech && c.pktsInState >= videoBurstSpeechMin &&
		c.pktCounter >= c.nextVideoBurst && c.videoInterval > 0 {
		burst := randPareto(videoBurstMin, videoBurstShape)
		if burst > videoBurstMax {
			burst = videoBurstMax
		}
		c.videoBurstRem = burst
		c.nextVideoBurst = c.pktCounter + uint64(c.videoInterval)
		c.videoInterval = randPareto(videoIntervalMin, videoIntervalShape)
		if c.videoInterval > videoIntervalMax {
			c.videoInterval = videoIntervalMax
		}
		if c.log != nil {
			c.log("[VIDEO] burst START — %d пакетов, след. burst через ~%d пакетов", burst, c.videoInterval)
		}
	}

	// --- Decide if THIS packet is video (only ~33% of burst, rest stays audio) ---
	isVideo := c.videoBurstRem > 0 && randRange(256) < videoChance
	if isVideo {
		c.videoBurstRem--
		if c.log != nil {
			c.log("[VIDEO] pkt seq=%d ssrc=%x payload=%d burst_rem=%d",
				seq, c.videoSSRC, plainLen, c.videoBurstRem)
			if c.videoBurstRem == 0 {
				c.log("[VIDEO] burst END")
			}
		}
	}

	// --- Compute plaintext sizes ---
	var extra int
	if isVideo {
		target := videoPktMinSize + randRange(videoPktMaxSize-videoPktMinSize+1)
		fillerLen := target - (videoLenPrefix + plainLen)
		if fillerLen < 0 {
			fillerLen = 0
		}
		extra = videoLenPrefix + fillerLen
	}

	padLen := 0
	if !isVideo && randRange(256) < paddingChance {
		padLen = paddingMin + randRange(paddingMax-paddingMin+1)
	}

	wireLen := overhead + plainLen + extra + padLen
	if len(buf) < wireLen {
		return 0, errors.New("rtpopus3:dst buffer too small")
	}

	// --- Video payload transformation (4B real_len + filler) ---
	if isVideo {
		copy(buf[headerLen+videoLenPrefix:headerLen+videoLenPrefix+plainLen], buf[headerLen:headerLen+plainLen])
		if plainLen < 0 || plainLen > 0xFFFF {
			return 0, errors.New("rtpopus3:plainLen overflow")
		}
		binary.BigEndian.PutUint32(buf[headerLen:headerLen+videoLenPrefix], uint32(plainLen))
		fillerLen := extra - videoLenPrefix
		fillerStart := headerLen + videoLenPrefix + plainLen
		for i := 0; i < fillerLen; i++ {
			buf[fillerStart+i] = byte(randRange(256)) //nolint:gosec // randRange(256)∈[0,255]
		}
	}

	// --- RTP header byte 0 ---
	buf[0] = rtpVerExt
	if padLen > 0 {
		buf[0] |= rtpPaddingBit
	}

	// --- RTP header byte 1 (PT + marker) ---
	var pt byte
	if isVideo {
		pt = byte(videoPT)
	} else {
		pt = byte(rtpPT)
		if startedSpeech && isSpeech {
			pt |= rtpMarker
		}
	}
	buf[1] = pt

	// --- Sequence ---
	binary.BigEndian.PutUint16(buf[2:4], seq)

	// --- Timestamp ---
	step := pickTsStep()
	ts := c.timestamp.Add(step) - step
	binary.BigEndian.PutUint32(buf[4:8], ts)

	// --- SSRC ---
	if isVideo {
		copy(buf[8:12], c.videoSSRC[:])
	} else {
		copy(buf[8:12], c.ssrc[:])
	}

	// --- RTP one-byte extensions ---
	buf[12] = 0xBE
	buf[13] = 0xDE
	binary.BigEndian.PutUint16(buf[14:16], 3)
	buf[16] = extAudioLevelHdr
	buf[17] = c.audioLevel()
	buf[18] = extTransportHdr
	tcc := uint16(c.tcc.Add(1) - 1) //nolint:gosec // RTP transport-cc seq wraps at 16 bits
	binary.BigEndian.PutUint16(buf[19:21], tcc)
	buf[21] = extAbsSendTimeHdr
	ast := c.absSendTime()
	buf[22] = byte(ast >> 16) //nolint:gosec // ast is 24-bit NTP timestamp
	buf[23] = byte(ast >> 8)  //nolint:gosec
	buf[24] = byte(ast)       //nolint:gosec
	buf[25], buf[26], buf[27] = 0, 0, 0

	// --- Nonce ---
	copy(buf[28:32], c.sessionID[:])
	ctr := c.counter.Add(1) - 1
	binary.BigEndian.PutUint64(buf[32:headerLen], ctr)

	// --- RTP padding bytes (audio only) ---
	if padLen > 0 {
		padStart := headerLen + plainLen + extra
		for i := 0; i < padLen; i++ {
			buf[padStart+i] = byte(randRange(256)) //nolint:gosec // randRange(256)∈[0,255]
		}
		buf[padStart+padLen-1] = byte(padLen) //nolint:gosec // padLen∈[1,4]
	}

	// --- AEAD ---
	nonce := buf[28:headerLen]
	aad := buf[:headerLen]
	plainEnd := headerLen + plainLen + extra + padLen
	c.state.aead.Seal(buf[headerLen:headerLen], nonce, buf[headerLen:plainEnd], aad)
	return wireLen, nil
}

func (c *Conn) Unwrap(wire, dst []byte) (int, error) {
	plain, err := c.UnwrapInPlace(wire)
	if err != nil {
		return 0, err
	}
	if len(plain) > len(dst) {
		return 0, errors.New("rtpopus3:dst buffer too small")
	}
	copy(dst[:len(plain)], plain)
	return len(plain), nil
}

func (c *Conn) UnwrapInPlace(wire []byte) ([]byte, error) {
	if len(wire) < overhead {
		return nil, errors.New("rtpopus3:packet too short")
	}
	nonce := wire[28:headerLen]
	aad := wire[:headerLen]
	ct := wire[headerLen:]

	plain, err := c.state.aead.Open(ct[:0], nonce, ct, aad)
	if err != nil {
		return nil, fmt.Errorf("rtpopus3:AEAD open: %w", err)
	}

	isVideo := (wire[1] & 0x7F) == videoPT
	if isVideo {
		if len(plain) < videoLenPrefix {
			return nil, errors.New("rtpopus3:video packet too short")
		}
		realLen := int(binary.BigEndian.Uint32(plain[:videoLenPrefix]))
		if realLen < 0 || videoLenPrefix+realLen > len(plain) {
			return nil, errors.New("rtpopus3:invalid video real_len")
		}
		if c.log != nil {
			seq := binary.BigEndian.Uint16(wire[2:4])
			ssrc := wire[8:12]
			c.log("[VIDEO] recv seq=%d ssrc=%x real_len=%d", seq, ssrc, realLen)
		}
		return plain[videoLenPrefix : videoLenPrefix+realLen], nil
	}

	if (wire[0]&rtpPaddingBit) != 0 && len(plain) > 0 {
		padLen := int(plain[len(plain)-1])
		if padLen > 0 && padLen < len(plain) {
			plain = plain[:len(plain)-padLen]
		}
	}

	return plain, nil
}

func GenKeyHex() (string, error) {
	key := make([]byte, KeyLen)
	if _, err := rand.Read(key); err != nil {
		return "", fmt.Errorf("rtpopus3:key gen: %w", err)
	}
	return hex.EncodeToString(key), nil
}

func DecodeKey(enabled bool, raw string) ([]byte, error) {
	if !enabled {
		return nil, nil
	}
	if raw == "" {
		return nil, errors.New("-obf-profile != none requires -obf-key")
	}
	key, err := hex.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("-obf-key invalid hex: %w", err)
	}
	if len(key) != KeyLen {
		return nil, fmt.Errorf("-obf-key must decode to %d bytes (got %d)", KeyLen, len(key))
	}
	return key, nil
}
