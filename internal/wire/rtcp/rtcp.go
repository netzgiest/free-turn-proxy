// Package rtcp реализует сборку compound RTCP-пакетов (SR+SDES)
// для инжекции в TURN relay-поток. VK DPI видит RTCP рядом с RTP —
// обязательный признак реального WebRTC.
package rtcp

import (
	"crypto/rand"
	"encoding/binary"
	"math"
	"time"
)

const (
	sdesCNAME = 1
)

// ntpTime преобразует time.Time в NTP 64-bit timestamp (сек+дробь, network order).
func ntpTime(t time.Time) (uint32, uint32) {
	sec := t.Unix() + 2208988800 // 1900 epoch offset
	frac := uint32(math.Floor(float64(t.Nanosecond()) * 4.294967296e-6))
	return uint32(sec), frac //nolint:gosec // NTP seconds fit in uint32 until 2036
}

// BuildCompoundSR собирает compound RTCP-пакет: Sender Report + SDES CNAME.
// Возвращает готовый байтовый срез.
//
// Формат:
//
//	SR (28 байт): 8B RTCP hdr + 20B SR body
//	SDES (≥12B):  8B RTCP hdr + 4B SSRC + 2B CNAME hdr + data + pad to 4B
func BuildCompoundSR(ssrc uint32, rtpTS uint32, pktCount, octCount uint32, cname []byte) []byte {
	if len(cname) == 0 {
		cname = []byte("rtc@webrtc")
	}
	if len(cname) > 255 {
		cname = cname[:255]
	}
	// SDES item size: 2 + len(cname)
	sdesItemLen := 2 + len(cname)
	// SDES chunk padded to 4 bytes: 4 (SSRC) + item, then pad to multiple of 4
	sdesBodyLen := 4 + sdesItemLen
	if rem := sdesBodyLen % 4; rem != 0 {
		sdesBodyLen += 4 - rem
	}
	// SDES packet: 4 words header + body/4 - 1 ?
	// RTCP header is 4 bytes: V=2, P, RC/SC, PT, length (words-1)
	// So SDES header = 4 bytes + 4 bytes SSRC + items + padding
	// Total SDES = 8 + (body_len - 4) padding to 4
	sdesLenWords := (8 + sdesBodyLen) / 4

	// SR: 8B hdr + 20B body = 28B = 7 words
	totalLen := 28 + 4*sdesLenWords
	buf := make([]byte, totalLen)

	// ---- SR (PT=200) ----
	binary.BigEndian.PutUint32(buf[0:4], 0x80C80006) // V=2, RC=0, PT=200, length=6
	binary.BigEndian.PutUint32(buf[4:8], ssrc)

	ntpSec, ntpFrac := ntpTime(time.Now())
	binary.BigEndian.PutUint32(buf[8:12], ntpSec)
	binary.BigEndian.PutUint32(buf[12:16], ntpFrac)
	binary.BigEndian.PutUint32(buf[16:20], rtpTS)
	binary.BigEndian.PutUint32(buf[20:24], pktCount)
	binary.BigEndian.PutUint32(buf[24:28], octCount)

	// ---- SDES (PT=202) ----
	sdesOff := 28
	binary.BigEndian.PutUint32(buf[sdesOff:sdesOff+4], 0x81CA0000|uint32(sdesLenWords-1)) //nolint:gosec // sdesLenWords fits uint32
	binary.BigEndian.PutUint32(buf[sdesOff+4:sdesOff+8], ssrc)

	itemOff := sdesOff + 8
	buf[itemOff] = sdesCNAME
	buf[itemOff+1] = byte(len(cname)) //nolint:gosec // len(cname) <= 255
	copy(buf[itemOff+2:], cname)

	return buf
}

// BuildReceiverReport собирает compound RTCP-пакет: Receiver Report + SDES CNAME.
// В реальном WebRTC RR шлются каждые ~1-5s с обеих сторон.
//
// Формат RR:
//
//	RR (32 байта): 8B RTCP hdr + 24B RR body (SSRC + 1 report block)
//	SDES (≥12B):  8B RTCP hdr + 4B SSRC + CNAME item + padding
func BuildReceiverReport(ssrc uint32, cname []byte) []byte {
	if len(cname) == 0 {
		cname = []byte("rtc@webrtc")
	}
	if len(cname) > 255 {
		cname = cname[:255]
	}

	// Report block: fraction_lost, cumulative_lost, ext_highest_seq, jitter, LSR, DLSR
	fractionLost := uint8(randRange(8)) //nolint:gosec // random stats, safe range
	cumLost := randRange(256)
	highestSeq := uint32(randRange(65536)) //nolint:gosec // random stats, safe range
	jitter := uint32(randRange(1000))      //nolint:gosec // random stats, safe range

	// SDES item
	sdesItemLen := 2 + len(cname)
	sdesBodyLen := 4 + sdesItemLen
	if rem := sdesBodyLen % 4; rem != 0 {
		sdesBodyLen += 4 - rem
	}
	sdesLenWords := (8 + sdesBodyLen) / 4

	// RR: 4B hdr + 4B sender SSRC + 24B report block = 32B = 8 words
	totalLen := 32 + 4*sdesLenWords
	buf := make([]byte, totalLen)

	// RR
	binary.BigEndian.PutUint32(buf[0:4], 0x81C90007) // V=2, RC=1, PT=201(RR), length=7
	binary.BigEndian.PutUint32(buf[4:8], ssrc)
	// Report block
	buf[8] = fractionLost
	buf[9] = byte(cumLost) //nolint:gosec // cumLost ∈ [0,255]
	binary.BigEndian.PutUint32(buf[12:16], highestSeq)
	binary.BigEndian.PutUint32(buf[16:20], jitter)
	// LSR = 0 (no last SR), DLSR = 0
	binary.BigEndian.PutUint32(buf[20:24], 0)
	binary.BigEndian.PutUint32(buf[24:28], 0)
	// Padding (4 bytes)
	binary.BigEndian.PutUint32(buf[28:32], 0)

	// SDES CNAME
	sdesOff := 32
	binary.BigEndian.PutUint32(buf[sdesOff:sdesOff+4], 0x81CA0000|uint32(sdesLenWords-1)) //nolint:gosec // sdesLenWords fits uint32
	binary.BigEndian.PutUint32(buf[sdesOff+4:sdesOff+8], ssrc)
	itemOff := sdesOff + 8
	buf[itemOff] = sdesCNAME
	buf[itemOff+1] = byte(len(cname)) //nolint:gosec // len(cname) ≤ 255
	copy(buf[itemOff+2:], cname)

	return buf
}

// BuildNACK собирает RTCP-пакет Generic NACK (RFC 4585, PT=205, FMT=1).
// Используется приёмником для запроса переотправки потерянных пакетов.
func BuildNACK(senderSSRC, mediaSSRC uint32, lostSeqs []uint16) []byte {
	if len(lostSeqs) == 0 {
		return nil
	}
	nFCI := len(lostSeqs)
	// Each FCI = 8 bytes: PID (2B) + BLP (2B) + 4B padding to keep it simple
	// RTCP header: 8B, FCI: nFCI*8B
	pktLen := 8 + nFCI*8
	// Ensure 32-bit alignment
	if pktLen%4 != 0 {
		pktLen += 4 - pktLen%4
	}
	buf := make([]byte, pktLen)
	words := pktLen/4 - 1
	binary.BigEndian.PutUint32(buf[0:4], 0x81CD0000|uint32(words)) //nolint:gosec // words fits uint32 // PT=205=RTPFB, FMT=1=NACK
	binary.BigEndian.PutUint32(buf[4:8], senderSSRC)
	binary.BigEndian.PutUint32(buf[8:12], mediaSSRC)

	for i, seq := range lostSeqs {
		off := 12 + i*8
		binary.BigEndian.PutUint16(buf[off:off+2], seq)
		binary.BigEndian.PutUint16(buf[off+2:off+4], 0) // BLP=0
	}
	return buf
}

// GenerateCNAME создаёт случайный CNAME как в Chromium WebRTC — base64 строка,
// без @ и без домена (rtc_base::CreateRandomString).
func GenerateCNAME() []byte {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	const cnameLen = 12
	b := make([]byte, cnameLen)
	if _, err := rand.Read(b); err != nil {
		return []byte("defaultCNAME12")
	}
	for i := range b {
		b[i] = alphabet[int(b[i])%len(alphabet)]
	}
	return b
}

func hexEncode(b []byte) string {
	const hex = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, v := range b {
		out[i*2] = hex[v>>4]
		out[i*2+1] = hex[v&0x0f]
	}
	return string(out)
}
