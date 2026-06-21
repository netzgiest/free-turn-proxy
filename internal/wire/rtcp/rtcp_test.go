package rtcp

import (
	"encoding/binary"
	"testing"
	"time"
)

func TestBuildCompoundSR(t *testing.T) {
	t.Parallel()

	pkt := BuildCompoundSR(0xDEAD, 123456, 100, 50000, []byte("test@host"))
	if len(pkt) < 44 {
		t.Fatalf("compound RTCP too short: %d bytes, want >= 44", len(pkt))
	}

	// SR header: V=2, RC=0, PT=200, length=6
	if pkt[0] != 0x80 || pkt[1] != 200 {
		t.Errorf("SR header mismatch: byte0=0x%02x byte1=%d, want 0x80 200", pkt[0], pkt[1])
	}
	length := binary.BigEndian.Uint16(pkt[2:4])
	if length != 6 {
		t.Errorf("SR length = %d words, want 6", length)
	}

	// SR SSRC
	ssrc := binary.BigEndian.Uint32(pkt[4:8])
	if ssrc != 0xDEAD {
		t.Errorf("SR SSRC = 0x%08x, want 0x0000DEAD", ssrc)
	}

	// SR body: NTP + RTP ts + pkt count + oct count
	rtpTS := binary.BigEndian.Uint32(pkt[16:20])
	if rtpTS != 123456 {
		t.Errorf("SR RTP timestamp = %d, want 123456", rtpTS)
	}
	pktCount := binary.BigEndian.Uint32(pkt[20:24])
	if pktCount != 100 {
		t.Errorf("SR packet count = %d, want 100", pktCount)
	}
	octCount := binary.BigEndian.Uint32(pkt[24:28])
	if octCount != 50000 {
		t.Errorf("SR octet count = %d, want 50000", octCount)
	}

	// SDES header (follows SR)
	sdesOff := 28
	if pkt[sdesOff] != 0x81 || pkt[sdesOff+1] != 202 {
		t.Errorf("SDES header mismatch: byte0=0x%02x byte1=%d, want 0x81 202",
			pkt[sdesOff], pkt[sdesOff+1])
	}

	// SDES SSRC
	sdesSsrc := binary.BigEndian.Uint32(pkt[sdesOff+4 : sdesOff+8])
	if sdesSsrc != 0xDEAD {
		t.Errorf("SDES SSRC = 0x%08x, want 0x0000DEAD", sdesSsrc)
	}

	// SDES CNAME item
	itemOff := sdesOff + 8
	if pkt[itemOff] != 1 {
		t.Errorf("SDES item type = %d, want CNAME=1", pkt[itemOff])
	}
	itemLen := int(pkt[itemOff+1])
	if itemLen != 9 {
		t.Errorf("CNAME length = %d, want 9", itemLen)
	}
	cname := string(pkt[itemOff+2 : itemOff+2+itemLen])
	if cname != "test@host" {
		t.Errorf("CNAME = %q, want %q", cname, "test@host")
	}

	// Проверяем что padding есть если нужно (total length кратен 4)
	if len(pkt)%4 != 0 {
		t.Errorf("compound packet length %d not multiple of 4", len(pkt))
	}
}

func TestBuildCompoundSR_Minimal(t *testing.T) {
	t.Parallel()
	pkt := BuildCompoundSR(0, 0, 0, 0, nil)
	if len(pkt) < 40 || len(pkt)%4 != 0 {
		t.Errorf("bad minimal RTCP: len=%d, mod4=%d", len(pkt), len(pkt)%4)
	}
	if pkt[1] != 200 {
		t.Errorf("PT = %d, want 200 (SR)", pkt[1])
	}
}

func TestGenerateCNAME(t *testing.T) {
	t.Parallel()
	c := GenerateCNAME()
	if len(c) != 12 {
		t.Errorf("CNAME length = %d, want 12", len(c))
	}
	for _, ch := range string(c) {
		if (ch < 'A' || ch > 'Z') && (ch < 'a' || ch > 'z') && (ch < '0' || ch > '9') && ch != '-' && ch != '_' {
			t.Errorf("CNAME contains invalid char %c (base64 url-safe)", ch)
		}
	}
}

func TestHexEncode(t *testing.T) {
	t.Parallel()
	result := hexEncode([]byte{0xAB, 0xCD})
	if result != "abcd" {
		t.Errorf("hex = %q, want %q", result, "abcd")
	}
}

func TestNTPTime(t *testing.T) {
	t.Parallel()
	sec, frac := ntpTime(time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC))
	if sec != 3913056000 { // 2024-01-01 = 3913056000 NTP seconds
		t.Errorf("NTP sec = %d, want 3913056000", sec)
	}
	if frac != 0 {
		t.Errorf("NTP frac = %d, want 0", frac)
	}
}
