package rtcp

import (
	"crypto/rand"
	"encoding/binary"
	"math/big"
	"net"
	"sync/atomic"
	"time"
)

const (
	rtcpIntervalBase = 500 * time.Millisecond
	rtcpIntervalMax  = 5 * time.Second
)

// Injector оборачивает net.PacketConn и периодически (каждые 0.5-5s)
// инжектит compound RTCP (SR+SDES) в поток, используя RTP-заголовки
// проходящих data-пакетов для актуализации статистики.
//
// VK DPI видит RTCP-пакеты рядом с RTP → неотличимо от real WebRTC.
// Никак не влияет на rtpopus/rtpopus2/rtpopus3 — работает поверх OBF-слоя.
type Injector struct {
	inner net.PacketConn
	peer  net.Addr
	cname []byte

	startTime time.Time
	lastRTCP  atomic.Int64 // unix nanos

	// парсинг RTP-заголовков проходящих пакетов
	ssrc     uint32
	rtpTS    uint32
	pktCount uint32
	octCount uint64

	// следующий интервал до RTCP (случайный)
	nextInterval atomic.Int64 // nanos

	overhead int // obf-профиль overhead для расчёта octCount

	logf func(format string, args ...any)
}

// rtcpRandInterval возвращает случайный интервал [rtcpIntervalBase, rtcpIntervalMax].
func rtcpRandInterval() int64 {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(rtcpIntervalMax-rtcpIntervalBase)))
	if err != nil {
		return int64(rtcpIntervalBase)
	}
	return int64(rtcpIntervalBase) + n.Int64()
}

// SetLogf устанавливает колбэк для отладочного логирования инжекции.
func (w *Injector) SetLogf(logf func(format string, args ...any)) { w.logf = logf }

// Wrap создаёт Injector, оборачивающий conn. peer — адрес TURN-пира.
// overhead — размер RTP-заголовка+расширения+nonce+tag obf-профиля
// (rtpopus3=56, rtpopus3-new=60). injector перехватывает WriteTo,
// обновляет статистику и периодически добавляет RTCP-пакеты.
func Wrap(conn net.PacketConn, peer net.Addr, overhead int) *Injector {
	if overhead < 12 {
		overhead = 56
	}
	inj := &Injector{
		inner:     conn,
		peer:      peer,
		cname:     GenerateCNAME(),
		startTime: time.Now(),
		overhead:  overhead,
	}
	inj.lastRTCP.Store(time.Now().UnixNano())
	inj.nextInterval.Store(rtcpRandInterval())
	return inj
}

// WriteTo перехватывает запись в relay, обновляет статистику из RTP-заголовка
// OBF-запакованного пакета и инжектит RTCP, если подошёл интервал.
func (w *Injector) WriteTo(b []byte, _ net.Addr) (int, error) {
	// Парсим SSRC и RTP timestamp из OBF-заголовка.
	// RTP header всегда в начале OBF-пакета: V=2, P, X, CC, M, PT, seq, ts, SSRC.
	if len(b) >= 12 && (b[0]&0xC0) == 0x80 { // V=2
		w.ssrc = binary.BigEndian.Uint32(b[8:12])
		w.rtpTS = binary.BigEndian.Uint32(b[4:8])
		w.pktCount++
		w.octCount += uint64(len(b) - w.overhead) //nolint:gosec // payload estimate, safe range
	}

	// Проверяем, не пора ли отправить RTCP.
	now := time.Now()
	if now.Sub(time.Unix(0, w.lastRTCP.Load())) >= time.Duration(w.nextInterval.Load()) {
		w.inject(now)
	}

	return w.inner.WriteTo(b, w.peer)
}

func (w *Injector) inject(now time.Time) {
	w.lastRTCP.Store(now.UnixNano())
	w.nextInterval.Store(rtcpRandInterval())

	sdesCname := w.cname
	if len(sdesCname) == 0 {
		sdesCname = []byte("rtc@webrtc")
	}

	// Чередуем SR+SDES (sender report) и RR+SDES (receiver report)
	if w.pktCount == 0 || randRange(256) < 192 { // ~75% SR, ~25% RR
		oct := uint32(w.octCount) //nolint:gosec // octCount tracked per-stream, fits uint32
		if oct > w.pktCount*1500 {
			oct = w.pktCount * 500
		}
		if w.logf != nil {
			w.logf("[RTCP] inject SR+SDES (pkt=%d oct=%d cname=%s next=%v)",
				w.pktCount, oct, sdesCname, time.Duration(w.nextInterval.Load()))
		}
		pkt := BuildCompoundSR(w.ssrc, w.rtpTS, w.pktCount, oct, sdesCname)
		if len(pkt) > 0 {
			_, _ = w.inner.WriteTo(pkt, w.peer)
		}
	} else {
		if w.logf != nil {
			w.logf("[RTCP] inject RR+SDES (ssrc=%x cname=%s next=%v)",
				w.ssrc, sdesCname, time.Duration(w.nextInterval.Load()))
		}
		pkt := BuildReceiverReport(w.ssrc, sdesCname)
		if len(pkt) > 0 {
			_, _ = w.inner.WriteTo(pkt, w.peer)
		}
	}
}

func randRange(n int) int {
	if n <= 0 {
		return 0
	}
	var b [1]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0
	}
	return int(b[0]) % n
}

// ReadFrom пробрасывает чтение без изменений.
func (w *Injector) ReadFrom(b []byte) (int, net.Addr, error) { return w.inner.ReadFrom(b) }

// Close закрывает внутреннее соединение.
func (w *Injector) Close() error { return w.inner.Close() }

// LocalAddr возвращает локальный адрес.
func (w *Injector) LocalAddr() net.Addr { return w.inner.LocalAddr() }

// SetDeadline пробрасывает дедлайн.
func (w *Injector) SetDeadline(t time.Time) error { return w.inner.SetDeadline(t) }

// SetReadDeadline пробрасывает read-дедлайн.
func (w *Injector) SetReadDeadline(t time.Time) error { return w.inner.SetReadDeadline(t) }

// SetWriteDeadline пробрасывает write-дедлайн.
func (w *Injector) SetWriteDeadline(t time.Time) error { return w.inner.SetWriteDeadline(t) }
