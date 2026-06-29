// Package shape реализует packet pacing для RTP-мимикрии:
// задержка между отправкой пакетов + случайный uniform jitter.
// Оборачивает net.PacketConn, вставляя sleep перед каждым WriteTo.
// Совместим с любой стороной — пакеты те же, только медленнее.
package shape

import (
	"net"
	"time"

	dtlsnet "github.com/pion/dtls/v3/pkg/net"

	"github.com/samosvalishe/free-turn-proxy/internal/randx"
)

// Shaper управляет межпакетной задержкой.
type Shaper struct {
	interval time.Duration
	lastSend time.Time
	burst    int // осталось пакетов в текущем burst (0 = не в burst)
	burstMax int // макс. пакетов в burst
}

// New создаёт Shaper. interval=0 отключает pacing.
func New(interval time.Duration) *Shaper {
	return &Shaper{
		interval: interval,
		burstMax: 3,
	}
}

// Wait блокируется до момента, когда можно отправить следующий пакет.
func (s *Shaper) Wait() {
	if s.interval <= 0 {
		return
	}
	// Burst-режим: первые burstMax пакетов идут без задержки.
	if s.burst > 0 {
		s.burst--
		s.lastSend = time.Now()
		return
	}
	if s.burstMax > 0 {
		// Случайно начинаем новый burst.
		if randx.Intn(100) < 30 { // 30% шанс начать burst
			s.burst = 1 + randx.Intn(s.burstMax)
			s.burst--
			s.lastSend = time.Now()
			return
		}
	}

	elapsed := time.Since(s.lastSend)
	wait := s.interval - elapsed
	if wait <= 0 {
		s.lastSend = time.Now()
		return
	}

	// Uniform jitter: ±10% от interval.
	jitter := time.Duration(float64(s.interval) * 0.10)
	if jitter > 0 {
		wait += time.Duration(randx.Intn(int(jitter)*2+1)) - jitter
	}
	if wait < 0 {
		wait = 0
	}
	time.Sleep(wait)
	s.lastSend = time.Now()
}

// ShapedPacketConn оборачивает net.PacketConn, применяя pacing к WriteTo.
// ReadFrom, Close и остальные методы пробрасываются без изменений.
type ShapedPacketConn struct {
	net.PacketConn
	shaper *Shaper
}

// WrapPacketConn оборачивает conn с межпакетной задержкой interval.
// interval=0 возвращает conn без обёртки (passthrough).
func WrapPacketConn(conn net.PacketConn, interval time.Duration) net.PacketConn {
	if interval <= 0 {
		return conn
	}
	return &ShapedPacketConn{
		PacketConn: conn,
		shaper:     New(interval),
	}
}

// WriteTo применяет pacing перед отправкой.
func (s *ShapedPacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	s.shaper.Wait()
	return s.PacketConn.WriteTo(b, addr)
}

// shapedPacketListener оборачивает dtlsnet.PacketListener, применяя pacing
// к WriteTo каждого принятого PacketConn.
type shapedPacketListener struct {
	inner    dtlsnet.PacketListener
	interval time.Duration
}

func (l *shapedPacketListener) Accept() (net.PacketConn, net.Addr, error) {
	pc, addr, err := l.inner.Accept()
	if err != nil {
		return pc, addr, err
	}
	return &ShapedPacketConn{PacketConn: pc, shaper: New(l.interval)}, addr, nil
}

func (l *shapedPacketListener) Close() error                   { return l.inner.Close() }
func (l *shapedPacketListener) Addr() net.Addr                 { return l.inner.Addr() }
func (l *shapedPacketListener) Unwrap() dtlsnet.PacketListener { return l.inner }

// WrapPacketListener оборачивает dtlsnet.PacketListener, добавляя pacing
// к WriteTo каждого принятого PacketConn (server-side shaping).
// interval=0 возвращает оригинальный listener без обёртки.
func WrapPacketListener(l dtlsnet.PacketListener, interval time.Duration) dtlsnet.PacketListener {
	if interval <= 0 {
		return l
	}
	return &shapedPacketListener{inner: l, interval: interval}
}
