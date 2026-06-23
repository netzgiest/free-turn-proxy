package rtpopus3

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	dtlsnet "github.com/pion/dtls/v3/pkg/net"
	pionudp "github.com/pion/transport/v4/udp"
)

const maxRTCPAttempts = 256

var bufPool = sync.Pool{
	New: func() any {
		b := make([]byte, MaxWire(1600))
		return &b
	},
}

func Listen(addr *net.UDPAddr, key []byte) (dtlsnet.PacketListener, error) {
	state, err := NewState(key)
	if err != nil {
		return nil, err
	}
	inner, err := pionudp.Listen("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("rtpopus3:udp listen: %w", err)
	}
	return &Listener{
		inner: dtlsnet.PacketListenerFromListener(inner),
		state: state,
	}, nil
}

// Listener — серверный dtlsnet.PacketListener с распаковкой rtpopus3.
type Listener struct {
	inner dtlsnet.PacketListener
	state *State
	logf  Logf
}

func (l *Listener) SetLogf(logf Logf) { l.logf = logf }

func (l *Listener) Accept() (net.PacketConn, net.Addr, error) {
	pc, addr, err := l.inner.Accept()
	if err != nil {
		return pc, addr, err
	}
	conn, err := NewConnFromState(l.state, true)
	if err != nil {
		return nil, addr, err
	}
	if l.logf != nil {
		conn.SetLogf(l.logf)
	}
	return &packetConn{inner: pc, conn: conn, logf: l.logf}, addr, nil
}

func (l *Listener) Close() error   { return l.inner.Close() }
func (l *Listener) Addr() net.Addr { return l.inner.Addr() }

// isRTCP проверяет, является ли пакет RTCP (SR/RR/SDES/BYE) по стандартному
// RTP/RTCP demux (RFC 5761 §4): V=2 и PT ∈ [200, 207].
func isRTCP(b []byte) bool {
	return len(b) >= 8 && (b[0]&0xC0) == 0x80 && b[1] >= 200 && b[1] <= 207
}

func rtcpPTName(pt byte) string {
	switch pt {
	case 200:
		return "SR"
	case 201:
		return "RR"
	case 202:
		return "SDES"
	case 203:
		return "BYE"
	case 204:
		return "APP"
	default:
		return fmt.Sprintf("PT=%d", pt)
	}
}

type packetConn struct {
	inner net.PacketConn
	conn  *Conn
	logf  Logf
}

func (c *packetConn) ReadFrom(p []byte) (int, net.Addr, error) {
	bpAny := bufPool.Get()
	bp, ok := bpAny.(*[]byte)
	if !ok {
		return 0, nil, errors.New("rtpopus3:bad bufPool type")
	}
	buf := *bp
	need := len(p) + overhead
	if cap(buf) < need {
		buf = make([]byte, need)
		*bp = buf
	}
	defer bufPool.Put(bp)

	for attempt := 0; attempt < maxRTCPAttempts; attempt++ {
		n, addr, err := c.inner.ReadFrom(buf[:cap(buf)])
		if err != nil {
			return 0, addr, err
		}
		wire := buf[:n]

		// RTCP-пакеты (инжектированные клиентом) не являются OBF;
		// пропускаем их — они не предназначены DTLS-слою.
		if isRTCP(wire) {
			if c.logf != nil {
				pt := wire[1]
				ssrc := binary.BigEndian.Uint32(wire[4:8])
				length := binary.BigEndian.Uint16(wire[2:4]) + 1
				c.logf("[RTCP] skip %s ssrc=%x words=%d", rtcpPTName(pt), ssrc, length)
			}
			continue
		}

		if len(wire) < overhead {
			return 0, addr, errors.New("rtpopus3:packet too short")
		}
		m, err := c.conn.Unwrap(wire, p)
		if err != nil {
			return 0, addr, err
		}
		return m, addr, nil
	}
	return 0, nil, errors.New("rtpopus3:too many non-OBF packets (RTCP flood?)")
}

func (c *packetConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	wireLen := c.conn.MaxWire(len(p))

	bpAny := bufPool.Get()
	bp, ok := bpAny.(*[]byte)
	if !ok {
		return 0, errors.New("rtpopus3:bad bufPool type")
	}
	out := *bp
	if cap(out) < wireLen {
		out = make([]byte, wireLen)
		*bp = out
	}
	out = out[:wireLen]
	defer bufPool.Put(bp)

	n, err := c.conn.WrapInto(out, p)
	if err != nil {
		return 0, err
	}
	if _, err := c.inner.WriteTo(out[:n], addr); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *packetConn) Close() error                       { return c.inner.Close() }
func (c *packetConn) LocalAddr() net.Addr                { return c.inner.LocalAddr() }
func (c *packetConn) SetDeadline(t time.Time) error      { return c.inner.SetDeadline(t) }
func (c *packetConn) SetReadDeadline(t time.Time) error  { return c.inner.SetReadDeadline(t) }
func (c *packetConn) SetWriteDeadline(t time.Time) error { return c.inner.SetWriteDeadline(t) }
