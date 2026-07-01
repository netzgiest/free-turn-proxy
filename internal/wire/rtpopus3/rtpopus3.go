// SPDX-License-Identifier: MIT

// Package rtpopus3 - wire-профиль обфускации с продвинутой RTP-мимикрией:
// пять one-byte extension (audio-level, transport-wide-cc, abs-send-time,
// MID, video frame marking), вариативный шаг timestamp, эмуляция потери
// пакетов (gaps в seq), VAD-модель silence/speech, эмуляция RTP padding
// с распределением по VAD, Comfort Noise (PT=13) во время молчания,
// RED (PT=127) для имитации FEC, мульти-SSRC видео-всплески VP8.
//
// Wire-формат (HeaderLen=44, Overhead=60):
//
//	[12B RTP hdr | 20B one-byte ext | 12B explicit nonce | AEAD ciphertext | 16B tag]
//
// RTP header (RFC 3550):
//
//	byte 0:    0x90|0x20   V=2, P=0/1, X=1, CC=0
//	byte 1:    M<<7 | PT   PT=111(opus)/13(CN)/127(RED)/96(VP8)
//	byte 2-3:  seq16 BE    монотонный с пропусками (loss simulation)
//	byte 4-7:  ts32 BE     вариативный шаг 480/960/1920 (10/20/40ms)
//	byte 8-11: SSRC        random per conn, видео-всплески отдельный SSRC
//
// RTP extension (RFC 8285 one-byte, 16 байт данных -> 4 слова):
//
//	byte 12-13: 0xBE 0xDE      профиль one-byte
//	byte 14-15: 0x0004         длина = 4 слова (16 байт данных)
//	byte 16:    0x10           ssrc-audio-level: id=1, len=0
//	byte 17:    0x80|level     VAD + level (-dBov)
//	byte 18:    0x21           transport-wide-cc: id=2, len=1
//	byte 19-20: tccSeq16       монотонный transport-cc sequence
//	byte 21:    0x32           abs-send-time: id=3, len=2
//	byte 22-24: abs_send_time  24-bit NTP timestamp
//	byte 25:    0x40           MID: id=4, len=0
//	byte 26:    'a'|'v'       media stream ID (audio/video)
//	byte 27:    0x50           video-frame-marking: id=5, len=0
//	byte 28:    mark_byte      S|E|I|0|T2|T1|T0|0
//	byte 29-31: 0x00           padding до 16 байт
//
// 12B explicit nonce = 4B sessionID || 8B counter (BE). MSB sessionID
// кодирует направление. AAD = первые 44 байт (RTP hdr || ext || nonce).
//
// VAD-распределение padding: во время речи 15% пакетов имеют P=1 и 2-8 байт,
// во время молчания 5% пакетов имеют 1-2 байта (как Comfort Noise).
package rtpopus3

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
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
	rtpExtLen = 20 // 4-word one-byte extension
	nonceLen  = 12
	tagLen    = 16
	headerLen = rtpHdrLen + rtpExtLen + nonceLen // 44
	overhead  = headerLen + tagLen               // 60
	rtpVerExt = 0x90                             // V=2, P=0, X=1, CC=0
	rtpPT     = 0x6F                             // M=0, PT=111 (opus)
	rtpMarker = 0x80                             // M=1

	rtpPaddingBit = 0x20 // P=1

	extAudioLevelHdr  = 0x10 // id=1, len=0 (1 byte data)
	extTransportHdr   = 0x21 // id=2, len=1 (2 bytes data)
	extAbsSendTimeHdr = 0x32 // id=3, len=2 (3 bytes data)
	extMIDHdr         = 0x40 // id=4, len=0 (1 byte data)
	extVideoMarkHdr   = 0x50 // id=5, len=0 (1 byte data)

	videoMarkS = 0x80 // start of frame
	videoMarkE = 0x40 // end of frame
	videoMarkI = 0x20 // keyframe

	// Comfort Noise (RFC 3389)
	cnPT            = 13
	cnSilenceChance = 76 // 76/256 ≈ 30% during silence

	// RED (RFC 2198)
	redPT           = 127
	redSpeechChance = 38 // 38/256 ≈ 15% during speech

	// VAD-based RTP padding
	speechPadChance = 38 // 38/256 ≈ 15% during speech
	speechPadMin    = 2
	speechPadMax    = 8
	cnPadChance     = 13 // 13/256 ≈ 5% during silence
	cnPadMin        = 1
	cnPadMax        = 2
	redPadMin       = 2
	redPadMax       = 6

	speechMinPkts     = 30
	speechShape       = 1.4
	silenceMeanPkts   = 15
	silenceTurnMean   = 75
	silenceTurnChance = 26

	gapIntervalMin = 50
	gapIntervalMax = 150
	gapSizeMin     = 1
	gapSizeMax     = 3

	tsStep20ms = 960
	tsStep10ms = 480
	tsStep40ms = 1920

	videoPT             = 96
	videoBurstMin       = 50
	videoBurstMax       = 200
	videoBurstShape     = 1.5
	videoIntervalMin    = 6000
	videoIntervalMax    = 60000
	videoIntervalShape  = 1.4
	videoPktMinSize     = 400
	videoPktMaxSize     = 900
	videoLenPrefix      = 4
	videoBurstSpeechMin = 30
	videoChance         = 85
)

func MaxWire(payloadLen int) int { return overhead + payloadLen + speechPadMax + videoPktMaxSize }

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
		nextGapAt:       gapIntervalMin + randInt(gapIntervalMax-gapIntervalMin+1),
		gapSize:         gapSizeMin + randInt(gapSizeMax-gapSizeMin+1),
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
	initialDelay := videoIntervalMin + randInt(2*videoIntervalMin)
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

func randInt(n int) int {
	if n <= 0 {
		return 0
	}
	var b [1]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("rtpopus3:rand: " + err.Error())
	}
	return int(b[0]) % n
}

// randFloat возвращает равномерное (0, 1] из crypto/rand.
func randFloat() float64 {
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
	u := randFloat()
	return shift + int(float64(shift)*math.Pow(1-u, -1/alpha))
}

// randExp генерирует экспоненциальное распределение с заданным mean.
// Используется для длительности пауз.
func randExp(mean int) int {
	u := randFloat()
	if u < 1e-15 {
		u = 1e-15
	}
	return int(-float64(mean) * math.Log(u))
}

func pickTsStep() uint32 {
	r := randInt(256)
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
	if randInt(256) < silenceTurnChance {
		dur = randExp(silenceTurnMean)
	} else {
		dur = randExp(silenceMeanPkts)
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
		return 0x80 | byte(20+randInt(31)) //nolint:gosec // bound: 20+[0,30] < 256
	}
	return byte(100 + randInt(28)) //nolint:gosec // bound: 100+[0,27] < 256
}

func (c *Conn) computeSeq() uint16 {
	seq := uint16(c.seq.Add(1) - 1) //nolint:gosec // RTP seq wraps at 16 bits
	c.nextGapAt--
	if c.nextGapAt > 0 {
		return seq
	}
	skip := uint32(c.gapSize) //nolint:gosec // gapSize ≤ 3
	c.seq.Add(skip)
	c.nextGapAt = gapIntervalMin + randInt(gapIntervalMax-gapIntervalMin+1)
	c.gapSize = gapSizeMin + randInt(gapSizeMax-gapSizeMin+1)
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

func videoMarking() byte {
	var mark byte
	r := randInt(10)
	switch {
	case r < 2:
		mark |= videoMarkS | videoMarkI
	case r < 4:
		mark |= videoMarkS
	case r < 6:
		mark |= videoMarkE
	}
	tid := byte(0) //nolint:gosec // tid ∈ [0,2]
	tr := randInt(10)
	if tr >= 7 && tr < 9 {
		tid = 1
	} else if tr >= 9 {
		tid = 2
	}
	return mark | (tid << 1)
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

	// VAD синхронизация с трафиком: не даём VAD уйти в silence,
	// пока идут пакеты. pktsInState растёт нормально — видео-всплески
	// продолжают работать.
	startedSpeech := c.updateAudioState()
	if c.audioState == stateSilence {
		c.audioState = stateSpeech
		startedSpeech = true
		c.nextStateSwitch = randPareto(speechMinPkts, speechShape)
		if c.log != nil {
			c.log("[VAD] traffic resumed — forced speech")
		}
	}
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
	isVideo := c.videoBurstRem > 0 && randInt(256) < videoChance
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

	// --- Determine CN/RED mode for audio ---
	isCN := !isVideo && c.audioState == stateSilence && randInt(256) < cnSilenceChance
	isRED := !isVideo && isSpeech && !isCN && randInt(256) < redSpeechChance

	// --- Compute plaintext sizes ---
	var extra int
	if isVideo {
		target := videoPktMinSize + randInt(videoPktMaxSize-videoPktMinSize+1)
		fillerLen := target - (videoLenPrefix + plainLen)
		if fillerLen < 0 {
			fillerLen = 0
		}
		extra = videoLenPrefix + fillerLen
	}

	padLen := 0
	if !isVideo {
		var padChance int
		var padMin, padMax int
		switch {
		case isRED:
			padChance = 256
			padMin = redPadMin
			padMax = redPadMax
		case isCN:
			padChance = cnPadChance
			padMin = cnPadMin
			padMax = cnPadMax
		default:
			padChance = speechPadChance
			padMin = speechPadMin
			padMax = speechPadMax
		}
		if randInt(256) < padChance {
			padLen = padMin + randInt(padMax-padMin+1)
		}
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
			buf[fillerStart+i] = byte(randInt(256)) //nolint:gosec // randInt(256)∈[0,255]
		}
	}

	// --- RTP header byte 0 ---
	buf[0] = rtpVerExt
	if padLen > 0 {
		buf[0] |= rtpPaddingBit
	}

	// --- RTP header byte 1 (PT + marker) ---
	var pt byte
	switch {
	case isVideo:
		pt = byte(videoPT)
	case isCN:
		pt = byte(cnPT)
	case isRED:
		pt = byte(redPT)
	default:
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

	// --- RTP one-byte extensions (4 words = 16 bytes data) ---
	buf[12] = 0xBE
	buf[13] = 0xDE
	binary.BigEndian.PutUint16(buf[14:16], 4)

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

	buf[25] = extMIDHdr
	if isVideo {
		buf[26] = 'v'
	} else {
		buf[26] = 'a'
	}

	buf[27] = extVideoMarkHdr
	if isVideo {
		buf[28] = videoMarking()
	} else {
		buf[28] = 0
	}

	buf[29], buf[30], buf[31] = 0, 0, 0

	// --- Nonce ---
	copy(buf[32:36], c.sessionID[:])
	ctr := c.counter.Add(1) - 1
	binary.BigEndian.PutUint64(buf[36:44], ctr)

	// --- RTP padding bytes ---
	if padLen > 0 {
		padStart := headerLen + plainLen + extra
		for i := 0; i < padLen; i++ {
			buf[padStart+i] = byte(randInt(256)) //nolint:gosec // randInt(256)∈[0,255]
		}
		buf[padStart+padLen-1] = byte(padLen) //nolint:gosec // padLen∈[1,8]
	}

	// --- AEAD ---
	nonce := buf[32:44]
	aad := buf[:44]
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
	nonce := wire[32:44]
	aad := wire[:44]
	ct := wire[44:]

	plain, err := c.state.aead.Open(ct[:0], nonce, ct, aad)
	if err != nil {
		return nil, fmt.Errorf("rtpopus3:AEAD open: %w", err)
	}

	if (wire[1] & 0x7F) == videoPT {
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
