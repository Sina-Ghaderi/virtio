package offloads

import (
	"encoding/binary"
	"os"
	"testing"

	"github.com/sina-ghaderi/tcpip"
	"github.com/sina-ghaderi/virtio/net"
)

// encodeMockHdr safely encodes the VirtioNetHdr into bytes for Decode() to consume.
// It tries LittleEndian (standard for Virtio) and falls back to BigEndian if Decode expects it.
func encodeMockHdr(target net.VirtioNetHdr) []byte {
	b := make([]byte, net.VirtioNetHdrLen)

	// Try standard LittleEndian
	b[0] = target.Flags
	b[1] = target.GsoType
	binary.LittleEndian.PutUint16(b[2:], target.HdrLen)
	binary.LittleEndian.PutUint16(b[4:], target.GsoSize)
	binary.LittleEndian.PutUint16(b[6:], target.CsumStart)
	binary.LittleEndian.PutUint16(b[8:], target.CsumOffset)

	var verify net.VirtioNetHdr
	verify.Decode(b)
	if verify.GsoType == target.GsoType && verify.HdrLen == target.HdrLen {
		return b
	}

	// Fallback to BigEndian if environment dictates
	b = make([]byte, net.VirtioNetHdrLen)
	b[0] = target.Flags
	b[1] = target.GsoType
	binary.BigEndian.PutUint16(b[2:], target.HdrLen)
	binary.BigEndian.PutUint16(b[4:], target.GsoSize)
	binary.BigEndian.PutUint16(b[6:], target.CsumStart)
	binary.BigEndian.PutUint16(b[8:], target.CsumOffset)
	return b
}

func makeVntBuf(vhdr net.VirtioNetHdr, packet []byte) []byte {
	buf := make([]byte, net.VirtioNetHdrLen+len(packet))
	copy(buf[:net.VirtioNetHdrLen], encodeMockHdr(vhdr))
	copy(buf[net.VirtioNetHdrLen:], packet)
	return buf
}

func TestNewVirtioGso(t *testing.T) {
	p := NewVirtioGso()
	if cap(p.buff) != maxOffloadSize {
		t.Fatalf("expected capacity %d, got %d", maxOffloadSize, cap(p.buff))
	}
	if p.offset != maxPacketLen {
		t.Fatalf("expected offset %d, got %d", maxPacketLen, p.offset)
	}
}

func TestProcessGso_Errors(t *testing.T) {
	tests := []struct {
		name      string
		vhdr      net.VirtioNetHdr
		packet    []byte
		errString string
	}{
		{
			name:      "short read of virtio packet (len < 1)",
			vhdr:      net.VirtioNetHdr{},
			packet:    []byte{},
			errString: "short read of virtio packet",
		},
		{
			name:      "short read of virtio ip header (IPv4 min len)",
			vhdr:      net.VirtioNetHdr{},
			packet:    make([]byte, 10), // Starts with 0x00 by default -> invalid version if not set
			errString: "invalid ip header version",
		},
		{
			name:      "invalid ip header version",
			vhdr:      net.VirtioNetHdr{},
			packet:    []byte{0x50, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, // Version 5
			errString: "invalid ip header version",
		},
		{
			name: "short read of virtio ip header (IPv4)",
			vhdr: net.VirtioNetHdr{},
			// IPv4 version (0x40), but length < 20
			packet:    []byte{0x40, 0, 0, 0, 0, 0},
			errString: "short read of virtio ip header",
		},
		{
			name: "short read of virtio ip header (IPv6)",
			vhdr: net.VirtioNetHdr{},
			// IPv6 version (0x60), but length < 40
			packet:    []byte{0x60, 0, 0, 0, 0, 0},
			errString: "short read of virtio ip header",
		},
		{
			name: "GSO_NONE short read of virtio ip packet (IPv4 total len)",
			vhdr: net.VirtioNetHdr{GsoType: net.VirtioNetHdrGsoNone},
			packet: func() []byte {
				pkt := make([]byte, 20)
				pkt[0] = 0x45
				binary.BigEndian.PutUint16(pkt[2:], 100) // Expects 100 bytes, but slice is 20
				return pkt
			}(),
			errString: "short read of virtio ip packet",
		},
		{
			name: "invalid ipv4 virtio header length (bounds)",
			vhdr: net.VirtioNetHdr{
				GsoType:   net.VirtioNetHdrGsoTCPV4, // Added explicitly
				CsumStart: 10,                       // < MinIPv4HdrLen
			},
			packet: func() []byte {
				pkt := make([]byte, 20)
				pkt[0] = 0x45
				return pkt
			}(),
			errString: "invalid ipv4 virtio header length",
		},
		{
			name: "invalid ipv4 virtio header length (mismatch IHL)",
			vhdr: net.VirtioNetHdr{
				GsoType:   net.VirtioNetHdrGsoTCPV4, // Added explicitly
				CsumStart: 24,
			},
			packet: func() []byte {
				pkt := make([]byte, 24)
				pkt[0] = 0x45 // IHL = 5 (20 bytes), but CsumStart = 24
				return pkt
			}(),
			errString: "invalid ipv4 virtio header length",
		},
		{
			name: "invalid ipv6 virtio header length",
			vhdr: net.VirtioNetHdr{
				GsoType:   net.VirtioNetHdrGsoUDPL4, // Added explicitly
				CsumStart: 20,                       // IPv6 header is exactly 40
			},
			packet: func() []byte {
				pkt := make([]byte, 40)
				pkt[0] = 0x60
				return pkt
			}(),
			errString: "invalid ipv6 virtio header length",
		},
		{
			name: "mismatched ipv6 version and gso type",
			vhdr: net.VirtioNetHdr{GsoType: net.VirtioNetHdrGsoTCPV6, CsumStart: 20},
			packet: func() []byte {
				pkt := make([]byte, 40)
				pkt[0] = 0x45 // IPv4
				return pkt
			}(),
			errString: "mismatched ipv6 version and gso type",
		},
		{
			name: "mismatched ipv4 version and gso type",
			vhdr: net.VirtioNetHdr{GsoType: net.VirtioNetHdrGsoTCPV4, CsumStart: 40},
			packet: func() []byte {
				pkt := make([]byte, 40)
				pkt[0] = 0x60 // IPv6
				return pkt
			}(),
			errString: "mismatched ipv4 version and gso type",
		},
		{
			name: "TCP invalid tcp header length (< Min)",
			vhdr: net.VirtioNetHdr{GsoType: net.VirtioNetHdrGsoTCPV4, CsumStart: 20, HdrLen: 30}, // 30 - 20 = 10 < 20
			packet: func() []byte {
				pkt := make([]byte, 40)
				pkt[0] = 0x45
				return pkt
			}(),
			errString: "invalid tcp header length",
		},
		{
			name: "TCP short read of virtio ip packet",
			vhdr: net.VirtioNetHdr{GsoType: net.VirtioNetHdrGsoTCPV4, CsumStart: 20, HdrLen: 40}, // expects 40
			packet: func() []byte {
				pkt := make([]byte, 30) // gives 30
				pkt[0] = 0x45
				return pkt
			}(),
			errString: "short read of virtio ip packet",
		},
		{
			name: "TCP invalid tcp header length (from offset)",
			vhdr: net.VirtioNetHdr{GsoType: net.VirtioNetHdrGsoTCPV4, CsumStart: 20, HdrLen: 40},
			packet: func() []byte {
				pkt := make([]byte, 40)
				pkt[0] = 0x45
				pkt[20+12] = 0x60 // Data Offset = 6 (24 bytes) != (40-20=20)
				return pkt
			}(),
			errString: "invalid tcp header length",
		},
		{
			name: "TCP invalid virtio tcp csum_offset",
			vhdr: net.VirtioNetHdr{GsoType: net.VirtioNetHdrGsoTCPV4, CsumStart: 20, HdrLen: 40, CsumOffset: 12}, // Must be 16
			packet: func() []byte {
				pkt := make([]byte, 40)
				pkt[0] = 0x45
				pkt[20+12] = 0x50 // Data offset = 5 (20 bytes)
				return pkt
			}(),
			errString: "invalid virtio tcp csum_offset",
		},
		{
			name: "UDP invalid udp header length",
			vhdr: net.VirtioNetHdr{GsoType: net.VirtioNetHdrGsoUDPL4, CsumStart: 20, HdrLen: 30}, // 30 - 20 = 10 != 8
			packet: func() []byte {
				pkt := make([]byte, 40)
				pkt[0] = 0x45
				return pkt
			}(),
			errString: "invalid udp header length",
		},
		{
			name: "UDP short read of virtio ip packet",
			vhdr: net.VirtioNetHdr{GsoType: net.VirtioNetHdrGsoUDPL4, CsumStart: 20, HdrLen: 28},
			packet: func() []byte {
				pkt := make([]byte, 25) // smaller than HdrLen 28
				pkt[0] = 0x45
				return pkt
			}(),
			errString: "short read of virtio ip packet",
		},
		{
			name: "UDP invalid virtio udp csum_offset",
			vhdr: net.VirtioNetHdr{GsoType: net.VirtioNetHdrGsoUDPL4, CsumStart: 20, HdrLen: 28, CsumOffset: 6}, // Must be 8
			packet: func() []byte {
				pkt := make([]byte, 28)
				pkt[0] = 0x45
				return pkt
			}(),
			errString: "invalid virtio udp csum_offset",
		},
		{
			name: "Unsupported GSO type",
			vhdr: net.VirtioNetHdr{GsoType: 99, CsumStart: 20},
			packet: func() []byte {
				pkt := make([]byte, 40)
				pkt[0] = 0x45
				return pkt
			}(),
			errString: "unsupported virtio gso type",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := NewVirtioGso()
			p.buff = makeVntBuf(tt.vhdr, tt.packet)
			err := p.processGso()
			if err == nil || err.Error() != tt.errString {
				t.Fatalf("expected error %q, got %v", tt.errString, err)
			}
		})
	}
}

func TestCopyGsoPackets(t *testing.T) {
	t.Run("IPv4 TCP Splitting Success", func(t *testing.T) {
		p := NewVirtioGso()

		// Construct 100 bytes: 20 (IP) + 20 (TCP) + 60 (Data)
		pkt := make([]byte, 100)
		pkt[0] = 0x45
		binary.BigEndian.PutUint16(pkt[4:], 0x1000) // ID
		pkt[20+12] = 0x50                           // TCP Data offset
		binary.BigEndian.PutUint32(pkt[20+4:], 50000)
		pkt[20+13] = tcpip.TCPFlagFIN | tcpip.TCPFlagPSH | 0x10

		p.buff = makeVntBuf(net.VirtioNetHdr{}, pkt) // Initial buffer
		// Bypass processGso by setting fields directly
		p.hdr = net.VirtioNetHdr{
			GsoType:    net.VirtioNetHdrGsoTCPV4,
			CsumStart:  20,
			CsumOffset: 16,
			HdrLen:     40,
			GsoSize:    40,
		}
		p.version = tcpip.IPv4
		p.proto = tcpip.ProtoTCP
		p.firstSeq = 50000
		p.offset = 40 // Start of payload
		p.counter = 0

		out := make([]byte, 200)
		n, err := p.copyGsoPackets(out)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// 40 (hdr) + 40 (payload1) + 40 (hdr) + 20 (payload2) = 140
		if n != 140 {
			t.Fatalf("expected 140 bytes, got %d", n)
		}

		// Verify TCP flags on first packet (cleared)
		if out[20+13]&(tcpip.TCPFlagFIN|tcpip.TCPFlagPSH) != 0 {
			t.Fatalf("flags not cleared on first packet")
		}
		// Verify IP ID on second packet (incremented)
		if binary.BigEndian.Uint16(out[80+4:]) != 0x1001 {
			t.Fatalf("IP ID not incremented")
		}
	})

	t.Run("IPv6 UDP Splitting Success", func(t *testing.T) {
		p := NewVirtioGso()

		// 40 (IPv6) + 8 (UDP) + 50 (Data)
		pkt := make([]byte, 98)
		pkt[0] = 0x60
		p.buff = makeVntBuf(net.VirtioNetHdr{}, pkt)

		p.hdr = net.VirtioNetHdr{
			GsoType:    net.VirtioNetHdrGsoUDPL4,
			CsumStart:  40,
			CsumOffset: 8,
			HdrLen:     48,
			GsoSize:    30, // splits into 30 + 20
		}
		p.version = tcpip.IPv6
		p.proto = tcpip.ProtoUDP
		p.offset = 48
		p.counter = 0

		out := make([]byte, 200)
		n, err := p.copyGsoPackets(out)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		// 48+30 + 48+20 = 146
		if n != 146 {
			t.Fatalf("expected 146 bytes, got %d", n)
		}
	})

	t.Run("Short Buffer Scenarios", func(t *testing.T) {
		p := NewVirtioGso()
		pkt := make([]byte, 100) // 40 hdr + 60 payload
		p.buff = makeVntBuf(net.VirtioNetHdr{}, pkt)
		p.hdr = net.VirtioNetHdr{HdrLen: 40, GsoSize: 40}
		p.offset = 40

		// Totally short buffer (can't hold first packet)
		_, err := p.copyGsoPackets(make([]byte, 50))
		if err != tcpip.ErrShortBuffer {
			t.Fatalf("expected ErrShortBuffer")
		}

		// Large enough for 1st packet (80 bytes), but not 2nd (60 bytes)
		n, err := p.copyGsoPackets(make([]byte, 100))
		if err != nil {
			t.Fatalf("expected nil error on partial copy")
		}
		if n != 80 {
			t.Fatalf("expected 80 bytes copied, got %d", n)
		}
		if p.offset != 80 { // 40 + 40
			t.Fatalf("offset not updated")
		}
	})

	t.Run("Already Drained", func(t *testing.T) {
		p := NewVirtioGso()
		p.buff = makeVntBuf(net.VirtioNetHdr{}, make([]byte, 50))
		p.offset = 100 // Exceeds packet length
		_, err := p.copyGsoPackets(make([]byte, 100))
		if err != errBuffDrained {
			t.Fatalf("expected errBuffDrained")
		}
	})
}

func TestCopyNonGsoPacket(t *testing.T) {
	t.Run("With Checksum Offload", func(t *testing.T) {
		p := NewVirtioGso()
		pkt := make([]byte, 30)
		p.buff = makeVntBuf(net.VirtioNetHdr{}, pkt)
		p.hdr = net.VirtioNetHdr{
			Flags:      net.VirtioNetHdrNeedsCSUM,
			CsumStart:  20,
			CsumOffset: 6,
		}

		out := make([]byte, 100)
		n, err := p.copyNonGsoPacket(out)
		if err != nil || n != 30 {
			t.Fatalf("copyNonGsoPacket failed")
		}
		if len(p.buff) != 0 {
			t.Fatalf("buffer not cleared")
		}
	})

	t.Run("Short Buffer", func(t *testing.T) {
		p := NewVirtioGso()
		p.buff = makeVntBuf(net.VirtioNetHdr{}, make([]byte, 30))
		_, err := p.copyNonGsoPacket(make([]byte, 10))
		if err != tcpip.ErrShortBuffer {
			t.Fatalf("expected ErrShortBuffer")
		}
	})
}

func TestRecv(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create pipe")
	}
	defer r.Close()
	defer w.Close()

	t.Run("Drained Buffer returns Drained Error", func(t *testing.T) {
		p := NewVirtioGso()
		_, err := p.copyPackets(make([]byte, 10))
		if err != errBuffDrained {
			t.Fatalf("expected errBuffDrained")
		}
	})

	t.Run("Short Read from File", func(t *testing.T) {
		p := NewVirtioGso()
		go func() { w.Write([]byte{0x01, 0x02}) }()
		_, err := p.Recv(r, make([]byte, 100))
		if err == nil || err.Error() != "short read of virtio header" {
			t.Fatalf("expected short read error, got %v", err)
		}
	})

	t.Run("Successful Read and Full Process", func(t *testing.T) {
		p := NewVirtioGso()

		// Create a valid VIRTIO_NET_HDR_GSO_NONE packet
		vhdr := net.VirtioNetHdr{GsoType: net.VirtioNetHdrGsoNone}
		pkt := make([]byte, 20)
		pkt[0] = 0x45
		binary.BigEndian.PutUint16(pkt[2:], 20) // Correct IPv4 total length
		fullBuf := makeVntBuf(vhdr, pkt)

		go func() { w.Write(fullBuf) }()

		out := make([]byte, 100)
		n, err := p.Recv(r, out)
		if err != nil {
			t.Fatalf("Recv failed: %v", err)
		}
		if n != 20 {
			t.Fatalf("expected 20 bytes copied, got %d", n)
		}
	})

	t.Run("File Read Error", func(t *testing.T) {
		p := NewVirtioGso()
		pr, pw, _ := os.Pipe()
		pw.Close() // EOF
		_, err := p.Recv(pr, make([]byte, 100))
		if err == nil {
			t.Fatalf("expected read error")
		}
	})

	t.Run("copyPackets returns non-Drained error directly", func(t *testing.T) {
		p := NewVirtioGso()
		// Setup pending payload
		p.buff = makeVntBuf(net.VirtioNetHdr{GsoType: net.VirtioNetHdrGsoNone}, make([]byte, 20))

		// Passing tiny buffer triggers ErrShortBuffer from copyPackets immediately, bypassing file read
		_, err := p.Recv(nil, make([]byte, 5))
		if err != tcpip.ErrShortBuffer {
			t.Fatalf("expected ErrShortBuffer, got %v", err)
		}
	})

	t.Run("processGso Error clears buffer", func(t *testing.T) {
		p := NewVirtioGso()

		// Create a deliberately invalid packet (bad IPv4 length to fail processGso)
		vhdr := net.VirtioNetHdr{GsoType: net.VirtioNetHdrGsoNone}
		pkt := make([]byte, 20)
		pkt[0] = 0x45
		binary.BigEndian.PutUint16(pkt[2:], 100) // Exceeds packet bounds
		fullBuf := makeVntBuf(vhdr, pkt)

		pr, pw, _ := os.Pipe()
		go func() {
			pw.Write(fullBuf)
			pw.Close()
		}()

		_, err := p.Recv(pr, make([]byte, 100))
		if err == nil || err.Error() != "short read of virtio ip packet" {
			t.Fatalf("expected processGso error, got %v", err)
		}

		// Ensure buffer was cleared on error
		if len(p.buff) != 0 {
			t.Fatalf("expected buffer to be cleared on processGso error")
		}
	})
}
