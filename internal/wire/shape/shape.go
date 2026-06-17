// Package shape реализует packet pacing для RTP-мимикрии:
// задержка между отправкой пакетов + случайный jitter.
// Оборачивает net.PacketConn, вставляя sleep перед каждым WriteTo.
// Совместим с любой стороной — пакеты те же, только медленнее.
package shape

import (
	"net"
	"time"

	"github.com/samosvalishe/free-turn-proxy/internal/randx"
)

// Shaper управляет межпакетной задержкой.
type Shaper struct {
	interval time.Duration
	lastSend time.Time
}

// New создаёт Shaper. interval=0 отключает pacing.
func New(interval time.Duration) *Shaper {
	return &Shaper{interval: interval}
}

// Wait блокируется до момента, когда можно отправить следующий пакет.
func (s *Shaper) Wait() {
	if s.interval <= 0 {
		return
	}
	elapsed := time.Since(s.lastSend)
	wait := s.interval - elapsed
	if wait <= 0 {
		s.lastSend = time.Now()
		return
	}
	// Случайный джиттер ±10% от interval, чтобы не было строго
	// равномерных промежутков — антифингерпринт.
	jitter := s.interval / 10
	if jitter > 0 {
		wait += time.Duration(randx.Intn(int(jitter)*2+1)) - jitter
		if wait < 0 {
			wait = 0
		}
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
