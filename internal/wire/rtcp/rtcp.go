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
	ptSR   = 200
	ptSDES = 202

	sdesCNAME = 1
)

// ntpTime преобразует time.Time в NTP 64-bit timestamp (сек+дробь, network order).
func ntpTime(t time.Time) (uint32, uint32) {
	sec := t.Unix() + 2208988800 // 1900 epoch offset
	frac := uint32(math.Floor(float64(t.Nanosecond()) * 4.294967296e-6))
	return uint32(sec), frac
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
	binary.BigEndian.PutUint32(buf[sdesOff:sdesOff+4], 0x81CA0000|uint32(sdesLenWords-1)) // V=2, SC=1, PT=202
	binary.BigEndian.PutUint32(buf[sdesOff+4:sdesOff+8], ssrc)

	itemOff := sdesOff + 8
	buf[itemOff] = sdesCNAME
	buf[itemOff+1] = byte(len(cname))
	copy(buf[itemOff+2:], cname)

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
