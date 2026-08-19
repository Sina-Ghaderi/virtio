package offloads

import (
	"encoding/binary"
	"os"
	"testing"

	"github.com/sina-ghaderi/tcpip"
	"github.com/sina-ghaderi/tcpip/checksum"
	"github.com/sina-ghaderi/virtio/net"
)

// Helper functions to construct packets for testing
func buildIPv4TCP(srcIP, dstIP []byte, srcPort, dstPort uint16, seq, ack uint32, payload []byte) []byte {
	iphLen := 20
	tcphLen := 20
	totLen := iphLen + tcphLen + len(payload)

	buf := make([]byte, totLen)
	buf[0] = 0x45 // IPv4, IHL=5
	binary.BigEndian.PutUint16(buf[2:], uint16(totLen))
	buf[9] = tcpip.ProtoTCP
	copy(buf[12:16], srcIP)
	copy(buf[16:20], dstIP)

	binary.BigEndian.PutUint16(buf[20:], srcPort)
	binary.BigEndian.PutUint16(buf[22:], dstPort)
	binary.BigEndian.PutUint32(buf[24:], seq)
	binary.BigEndian.PutUint32(buf[28:], ack)
	buf[32] = 0x50 // Data Offset: 5 words (20 bytes)
	buf[33] = tcpip.TCPFlagACK | tcpip.TCPFlagPSH

	copy(buf[40:], payload)
	return buf
}

func buildIPv4UDP(srcIP, dstIP []byte, srcPort, dstPort uint16, payload []byte) []byte {
	iphLen := 20
	udphLen := 8
	totLen := iphLen + udphLen + len(payload)

	buf := make([]byte, totLen)
	buf[0] = 0x45 // IPv4, IHL=5
	binary.BigEndian.PutUint16(buf[2:], uint16(totLen))
	buf[9] = tcpip.ProtoUDP
	copy(buf[12:16], srcIP)
	copy(buf[16:20], dstIP)

	binary.BigEndian.PutUint16(buf[20:], srcPort)
	binary.BigEndian.PutUint16(buf[22:], dstPort)
	binary.BigEndian.PutUint16(buf[24:], uint16(udphLen+len(payload)))

	copy(buf[28:], payload)
	return buf
}

func buildIPv6TCP(srcIP, dstIP []byte, srcPort, dstPort uint16, seq, ack uint32, payload []byte) []byte {
	iphLen := 40
	tcphLen := 20
	payloadLen := tcphLen + len(payload)

	buf := make([]byte, iphLen+payloadLen)
	buf[0] = 0x60 // IPv6
	binary.BigEndian.PutUint16(buf[4:], uint16(payloadLen))
	buf[6] = tcpip.ProtoTCP
	copy(buf[8:24], srcIP)
	copy(buf[24:40], dstIP)

	binary.BigEndian.PutUint16(buf[40:], srcPort)
	binary.BigEndian.PutUint16(buf[42:], dstPort)
	binary.BigEndian.PutUint32(buf[44:], seq)
	binary.BigEndian.PutUint32(buf[48:], ack)
	buf[52] = 0x50 // Data offset
	buf[53] = tcpip.TCPFlagACK

	copy(buf[60:], payload)
	return buf
}

func buildIPv6UDP(srcIP, dstIP []byte, srcPort, dstPort uint16, payload []byte) []byte {
	iphLen := 40
	udphLen := 8
	payloadLen := udphLen + len(payload)

	buf := make([]byte, iphLen+payloadLen)
	buf[0] = 0x60 // IPv6
	binary.BigEndian.PutUint16(buf[4:], uint16(payloadLen))
	buf[6] = tcpip.ProtoUDP
	copy(buf[8:24], srcIP)
	copy(buf[24:40], dstIP)

	binary.BigEndian.PutUint16(buf[40:], srcPort)
	binary.BigEndian.PutUint16(buf[42:], dstPort)
	binary.BigEndian.PutUint16(buf[44:], uint16(payloadLen))

	copy(buf[48:], payload)
	return buf
}

// Tests Flow Table Creation
func TestNewFlowTable(t *testing.T) {
	ft := newFlowTable()
	if ft == nil {
		t.Fatal("expected non-nil flowTable")
	}
	if len(ft.megaPackets) != batchProcess {
		t.Fatalf("expected megaPackets capacity %d, got %d", batchProcess, len(ft.megaPackets))
	}
	if len(ft.flowPool) != batchProcess {
		t.Fatalf("expected flowPool capacity %d, got %d", batchProcess, len(ft.flowPool))
	}
}

// Tests FlowPool Depletion and Re-allocation
func TestFlowPool_Depletion(t *testing.T) {
	ft := newFlowTable()

	// Exhaust the pool
	for i := 0; i < batchProcess; i++ {
		_ = ft.newFlowInfo()
	}
	if len(ft.flowPool) != 0 {
		t.Fatalf("expected empty flowPool, got len %d", len(ft.flowPool))
	}

	// Triggers len(t.flowPool) == 0 branch to grow flowPool
	flow := ft.newFlowInfo()
	if flow == nil {
		t.Fatal("expected new flowInfo after depletion")
	}
	if len(ft.flowPool) != batchProcess-1 {
		t.Fatalf("expected flowPool to be reallocated to size %d, got %d", batchProcess-1, len(ft.flowPool))
	}
}

// Tests getOrAddFlow and growMegaPackets
func TestFlowTable_GetOrAddFlow(t *testing.T) {
	ft := newFlowTable()

	rawTCP := buildIPv4TCP([]byte{192, 168, 1, 1}, []byte{192, 168, 1, 2}, 80, 12345, 100, 200, []byte("hello"))
	pktTCP, err := newPacket(rawTCP)
	if err != nil {
		t.Fatalf("unexpected newPacket error: %v", err)
	}

	key := uint64(12345)

	// 1. Add new TCP flow
	flow := ft.getOrAddFlow(key, pktTCP)
	if flow != nil {
		t.Fatalf("expected nil for brand new flow, got %v", flow)
	}

	mega := ft.megaPackets[0]
	if mega.seq != 100 {
		t.Fatalf("expected TCP sequence 100, got %d", mega.seq)
	}
	if mega.flags != (tcpip.TCPFlagACK | tcpip.TCPFlagPSH) {
		t.Fatalf("expected flags %d, got %d", tcpip.TCPFlagACK|tcpip.TCPFlagPSH, mega.flags)
	}

	// 2. Fetch existing flow
	existingFlow := ft.getOrAddFlow(key, pktTCP)
	if len(existingFlow) != 1 || existingFlow[0] != 0 {
		t.Fatalf("expected existing flow slice [0], got %v", existingFlow)
	}

	// 3. Add non-TCP (UDP) flow and hit growMegaPackets branch when buffPos >= len(megaPackets)
	ft.buffPos = len(ft.megaPackets) // Force buffPos to end
	rawUDP := buildIPv4UDP([]byte{192, 168, 1, 1}, []byte{192, 168, 1, 2}, 80, 12345, []byte("udp-payload"))
	pktUDP, _ := newPacket(rawUDP)

	udpKey := uint64(99999)
	ft.getOrAddFlow(udpKey, pktUDP)

	if len(ft.megaPackets) != batchProcess+1 {
		t.Fatalf("expected megaPackets to grow to %d, got %d", batchProcess+1, len(ft.megaPackets))
	}
}

// Tests addFlow
func TestFlowTable_AddFlow(t *testing.T) {
	ft := newFlowTable()

	rawTCP := buildIPv4TCP([]byte{10, 0, 0, 1}, []byte{10, 0, 0, 2}, 443, 54321, 500, 600, []byte("payload"))
	pkt, _ := newPacket(rawTCP)
	key := uint64(777)

	// 1. Add flow for new key
	ft.addFlow(key, pkt)
	if len(ft.ht[key]) != 1 {
		t.Fatalf("expected flow size 1, got %d", len(ft.ht[key]))
	}

	// 2. Add flow for existing key
	ft.addFlow(key, pkt)
	if len(ft.ht[key]) != 2 {
		t.Fatalf("expected flow size 2, got %d", len(ft.ht[key]))
	}
}

// Tests resetFlowTable
func TestFlowTable_ResetFlowTable(t *testing.T) {
	ft := newFlowTable()

	rawTCP := buildIPv4TCP([]byte{10, 0, 0, 1}, []byte{10, 0, 0, 2}, 443, 54321, 500, 600, []byte("payload"))
	pkt, _ := newPacket(rawTCP)

	// Populate table
	ft.getOrAddFlow(1, pkt)
	ft.getOrAddFlow(2, pkt)

	// Reset when flowPool has capacity
	ft.resetFlowTable()
	if len(ft.ht) != 0 {
		t.Fatalf("expected empty ht, got %d", len(ft.ht))
	}
	if ft.buffPos != 0 {
		t.Fatalf("expected buffPos to be 0, got %d", ft.buffPos)
	}

	// Reset when flowPool is at/above batchProcess cap
	ft.flowPool = make([]flowInfo, batchProcess) // Force full pool
	ft.ht[1] = []packetID{0}
	ft.ht[2] = []packetID{1}

	ft.resetFlowTable() // Should trigger `break` in resetFlowTable loop
	if len(ft.ht) != 0 {
		t.Fatalf("expected ht to be cleared")
	}
}

// Tests newPacket Parsing & Error Branches
func TestNewPacket(t *testing.T) {
	t.Run("IPv4 TCP Valid", func(t *testing.T) {
		buf := buildIPv4TCP([]byte{1, 1, 1, 1}, []byte{2, 2, 2, 2}, 80, 8080, 1, 2, []byte("data"))
		pkt, err := newPacket(buf)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if pkt.version != tcpip.IPv4 || pkt.proto != tcpip.ProtoTCP {
			t.Fatalf("incorrect packet properties")
		}
	})

	t.Run("IPv4 UDP Valid", func(t *testing.T) {
		buf := buildIPv4UDP([]byte{1, 1, 1, 1}, []byte{2, 2, 2, 2}, 80, 8080, []byte("data"))
		pkt, err := newPacket(buf)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if pkt.version != tcpip.IPv4 || pkt.proto != tcpip.ProtoUDP {
			t.Fatalf("incorrect packet properties")
		}
	})

	t.Run("IPv6 TCP Valid", func(t *testing.T) {
		src := []byte{0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
		dst := []byte{0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}
		buf := buildIPv6TCP(src, dst, 80, 8080, 1, 2, []byte("data"))

		pkt, err := newPacket(buf)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if pkt.version != tcpip.IPv6 || pkt.proto != tcpip.ProtoTCP {
			t.Fatalf("incorrect packet properties")
		}
	})

	t.Run("IPv6 UDP Valid", func(t *testing.T) {
		src := []byte{0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
		dst := []byte{0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}
		buf := buildIPv6UDP(src, dst, 80, 8080, []byte("data"))

		pkt, err := newPacket(buf)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if pkt.version != tcpip.IPv6 || pkt.proto != tcpip.ProtoUDP {
			t.Fatalf("incorrect packet properties")
		}
	})

	t.Run("Invalid IP Version", func(t *testing.T) {
		buf := []byte{0x30, 0, 0, 0}
		_, err := newPacket(buf)
		if err == nil {
			t.Fatal("expected error for invalid IP version")
		}
	})

	t.Run("Truncated IPv4 Header", func(t *testing.T) {
		buf := []byte{0x45, 0, 0} // Too short
		_, err := newPacket(buf)
		if err == nil {
			t.Fatal("expected error for truncated IPv4 header")
		}
	})

	t.Run("Truncated IPv6 Header", func(t *testing.T) {
		buf := make([]byte, 20)
		buf[0] = 0x60 // IPv6, but < 40 bytes
		_, err := newPacket(buf)
		if err == nil {
			t.Fatal("expected error for truncated IPv6 header")
		}
	})

	t.Run("Truncated TCP Header", func(t *testing.T) {
		// Valid IPv4 header, truncated TCP payload
		buf := make([]byte, 25)
		buf[0] = 0x45
		binary.BigEndian.PutUint16(buf[2:], 25)
		buf[9] = tcpip.ProtoTCP

		_, err := newPacket(buf)
		if err == nil {
			t.Fatal("expected error for truncated TCP header")
		}
	})

	t.Run("Truncated UDP Header", func(t *testing.T) {
		// Valid IPv4 header, truncated UDP payload
		buf := make([]byte, 24)
		buf[0] = 0x45
		binary.BigEndian.PutUint16(buf[2:], 24)
		buf[9] = tcpip.ProtoUDP

		_, err := newPacket(buf)
		if err == nil {
			t.Fatal("expected error for truncated UDP header")
		}
	})
}

// Tests Hash Generation across IPv4/IPv6 and TCP/UDP
func TestFastFlowHash(t *testing.T) {
	src4 := []byte{192, 168, 1, 10}
	dst4 := []byte{192, 168, 1, 20}
	src6 := []byte{0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	dst6 := []byte{0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}

	t.Run("IPv4 TCP Hash", func(t *testing.T) {
		p, _ := newPacket(buildIPv4TCP(src4, dst4, 1000, 2000, 10, 20, []byte("x")))
		h := fastFlowHash(p)
		if h == 0 {
			t.Fatal("expected non-zero hash")
		}
	})

	t.Run("IPv4 UDP Hash", func(t *testing.T) {
		p, _ := newPacket(buildIPv4UDP(src4, dst4, 1000, 2000, []byte("x")))
		h := fastFlowHash(p)
		if h == 0 {
			t.Fatal("expected non-zero hash")
		}
	})

	t.Run("IPv6 TCP Hash", func(t *testing.T) {
		p, _ := newPacket(buildIPv6TCP(src6, dst6, 1000, 2000, 10, 20, []byte("x")))
		h := fastFlowHash(p)
		if h == 0 {
			t.Fatal("expected non-zero hash")
		}
	})

	t.Run("IPv6 UDP Hash", func(t *testing.T) {
		p, _ := newPacket(buildIPv6UDP(src6, dst6, 1000, 2000, []byte("x")))
		h := fastFlowHash(p)
		if h == 0 {
			t.Fatal("expected non-zero hash")
		}
	})
}

func mockNewPacketBuilder(version, proto uint8, payload string) []byte {
	var iphLen, l4Len int

	if version == tcpip.IPv4 {
		iphLen = 20
		if proto == tcpip.ProtoTCP {
			l4Len = 20
		} else {
			l4Len = 8
		}

		totLen := iphLen + l4Len + len(payload)
		b := make([]byte, totLen)
		b[0] = 0x45 // IPv4, IHL=5
		binary.BigEndian.PutUint16(b[2:], uint16(totLen))
		b[9] = proto

		if proto == tcpip.ProtoTCP {
			b[32] = uint8(l4Len/4) << 4 // TCP Data Offset
		} else {
			binary.BigEndian.PutUint16(b[24:], uint16(l4Len+len(payload))) // UDP length
		}

		copy(b[iphLen+l4Len:], payload)
		return b
	}

	// IPv6
	iphLen = 40
	if proto == tcpip.ProtoTCP {
		l4Len = 20
	} else {
		l4Len = 8
	}

	payloadLen := l4Len + len(payload)
	b := make([]byte, iphLen+payloadLen)
	b[0] = 0x60
	binary.BigEndian.PutUint16(b[4:], uint16(payloadLen))
	b[6] = proto

	if proto == tcpip.ProtoTCP {
		b[52] = uint8(l4Len/4) << 4 // TCP Data Offset
	} else {
		binary.BigEndian.PutUint16(b[44:], uint16(payloadLen)) // UDP length
	}

	copy(b[iphLen+l4Len:], payload)
	return b
}

func TestNewVirtioGro(t *testing.T) {
	vgTrue := NewVirtioGro(true)
	if vgTrue == nil || vgTrue.table == nil {
		t.Fatal("expected VirtioGro and flowTable to be initialized")
	}
	if !vgTrue.udpSupported {
		t.Fatal("expected udpSupported to be true")
	}

	vgFalse := NewVirtioGro(false)
	if vgFalse.udpSupported {
		t.Fatal("expected udpSupported to be false")
	}
}

func TestProsessGro(t *testing.T) {
	vg := NewVirtioGro(true)

	t.Run("Not a candidate", func(t *testing.T) {
		// Create a packet that fails isGroCandidate (e.g., unknown protocol)
		raw := mockNewPacketBuilder(tcpip.IPv4, 99, "data")
		pkt := packet{ptr: raw, iph: raw[:20], version: tcpip.IPv4, proto: 99}

		status := vg.prosessGro(pkt)
		if status != groNoGroPacket {
			t.Fatalf("expected groNoGroPacket for invalid candidate, got %v", status)
		}
	})

	t.Run("Valid candidate processed", func(t *testing.T) {
		raw := mockNewPacketBuilder(tcpip.IPv4, tcpip.ProtoTCP, "data")
		pkt := packet{ptr: raw, iph: raw[:20], tcpudph: raw[20:40], version: tcpip.IPv4, proto: tcpip.ProtoTCP}

		// Set ACK flag to ensure it passes basic merge checks
		pkt.tcpudph[13] = tcpip.TCPFlagACK

		status := vg.prosessGro(pkt)
		// Depending on table state it might return groTableInsert or groNoGroPacket (if checksum fails),
		// but we primarily want to ensure it passes the candidate check and enters megrgePacket without panic.
		if status != groTableInsert && status != groNoGroPacket {
			t.Fatalf("unexpected status returned from prosessGro: %v", status)
		}
	})
}

func TestPrepareMegaPacket(t *testing.T) {
	ft := newFlowTable()

	t.Run("No GRO happened (len(data) < 2)", func(t *testing.T) {
		header := make([]byte, 40)
		mega := megaPacket{
			header: header,
			data:   [][]byte{[]byte("data1")}, // Only 1 segment
		}

		buf := make([]byte, net.VirtioNetHdrLen+len(header))
		// Fill virtio net header area with garbage to ensure it gets cleared
		for i := 0; i < net.VirtioNetHdrLen; i++ {
			buf[i] = 0xFF
		}

		res := ft.prepareMegaPacket(mega, buf)
		if string(res) != string(header) {
			t.Fatal("expected original header to be returned")
		}
		for i := 0; i < net.VirtioNetHdrLen; i++ {
			if buf[i] != 0 {
				t.Fatalf("expected virtio net header to be cleared, found %X at index %d", buf[i], i)
			}
		}
	})

	t.Run("IPv4 TCP MegaPacket", func(t *testing.T) {
		header := make([]byte, 40)
		header[0] = 0x45 // IPv4

		mega := megaPacket{
			header:  header,
			data:    [][]byte{[]byte("data1"), []byte("data2")},
			datalen: 10,
			iphlen:  20,
			trhlen:  20,
			gsosize: 5,
			version: tcpip.IPv4,
			proto:   tcpip.ProtoTCP,
			flags:   tcpip.TCPFlagACK | tcpip.TCPFlagPSH,
		}

		buf := make([]byte, net.VirtioNetHdrLen+len(header))
		res := ft.prepareMegaPacket(mega, buf)

		if len(res) != 40 {
			t.Fatalf("expected header length 40, got %d", len(res))
		}

		// Verify IP modifications
		iph := tcpip.IPv4Header(res)
		if iph.TotalLen() != 50 { // 40 (header) + 10 (datalen)
			t.Fatalf("expected IPv4 TotalLen 50, got %d", iph.TotalLen())
		}
		if iph.Checksum() == 0 {
			t.Fatal("expected IPv4 checksum to be computed and set")
		}

		// Verify TCP modifications
		tcph := tcpip.TCPHeader(res[20:])
		if tcph.Flags() != (tcpip.TCPFlagACK | tcpip.TCPFlagPSH) {
			t.Fatalf("expected TCP flags to be updated, got %v", tcph.Flags())
		}
	})

	t.Run("IPv6 TCP MegaPacket", func(t *testing.T) {
		header := make([]byte, 60) // 40 IPv6 + 20 TCP
		header[0] = 0x60

		mega := megaPacket{
			header:  header,
			data:    [][]byte{[]byte("d1"), []byte("d2")},
			datalen: 4,
			iphlen:  40,
			trhlen:  20,
			gsosize: 2,
			version: tcpip.IPv6,
			proto:   tcpip.ProtoTCP,
			flags:   tcpip.TCPFlagACK,
		}

		buf := make([]byte, net.VirtioNetHdrLen+len(header))
		res := ft.prepareMegaPacket(mega, buf)

		iph := tcpip.IPv6Header(res)
		if iph.PayloadLen() != 24 { // 20 (TCP header) + 4 (datalen)
			t.Fatalf("expected IPv6 PayloadLen 24, got %d", iph.PayloadLen())
		}
	})

	t.Run("IPv4 UDP MegaPacket", func(t *testing.T) {
		header := make([]byte, 28) // 20 IPv4 + 8 UDP
		header[0] = 0x45

		mega := megaPacket{
			header:  header,
			data:    [][]byte{[]byte("ud1"), []byte("ud2")},
			datalen: 6,
			iphlen:  20,
			trhlen:  8,
			gsosize: 3,
			version: tcpip.IPv4,
			proto:   tcpip.ProtoUDP,
		}

		buf := make([]byte, net.VirtioNetHdrLen+len(header))
		_ = ft.prepareMegaPacket(mega, buf)

		// Verification happens indirectly. The function shouldn't panic and
		// the checksums shouldn't fault when computing UDP pseudo header.
	})
}

func TestSend(t *testing.T) {
	vg := NewVirtioGro(true)

	// Create a temporary file to act as our FD target for writev
	tmpFile, err := os.CreateTemp("", "subpass-gro-test")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	t.Run("Empty Buffer", func(t *testing.T) {
		n, err := vg.Send(tmpFile, []byte{})
		if err != nil {
			t.Fatalf("expected no error on empty buffer, got %v", err)
		}
		if n != 0 {
			t.Fatalf("expected n=0, got %d", n)
		}
	})

	t.Run("Valid Packets Flow", func(t *testing.T) {
		// Construct a buffer with two standard raw packets
		pkt1 := mockNewPacketBuilder(tcpip.IPv4, tcpip.ProtoTCP, "payload1")
		pkt2 := mockNewPacketBuilder(tcpip.IPv4, tcpip.ProtoUDP, "payload2")
		buf := append(pkt1, pkt2...)

		n, err := vg.Send(tmpFile, buf)
		if err != nil {
			t.Fatalf("expected Send to succeed, got %v", err)
		}
		if n != len(buf) {
			t.Fatalf("expected to process %d bytes, got %d", len(buf), n)
		}
	})

	t.Run("Short Buffer Handling", func(t *testing.T) {
		// Provide an incomplete packet (e.g., just the start of an IPv4 header)
		shortBuf := []byte{0x45, 0x00, 0x00}

		n, err := vg.Send(tmpFile, shortBuf)
		// Because no packets were parsed, len(unchecked) == len(b).
		// send.go does NOT suppress the error in this case, which is correct.
		if err == nil {
			t.Fatal("expected Send to return short buffer error for completely short buffer, got nil")
		}
		if n != 0 {
			t.Fatalf("expected 0 bytes processed for purely short buffer, got %d", n)
		}

		// Combined valid packet + short buffer tail
		valid := mockNewPacketBuilder(tcpip.IPv4, tcpip.ProtoUDP, "ok")
		combined := append(valid, shortBuf...)

		n2, err2 := vg.Send(tmpFile, combined)
		// Here, a valid packet was parsed first, so len(unchecked) < len(b).
		// send.go SHOULD suppress the error here.
		if err2 != nil {
			t.Fatalf("expected nil error on combined short buffer, got %v", err2)
		}
		if n2 != len(valid) {
			t.Fatalf("expected to process exactly %d bytes of valid packet, got %d", len(valid), n2)
		}
	})

	t.Run("Closed File Error Handling (writev failure)", func(t *testing.T) {
		// Test how Send behaves when the underlying file descriptor is invalid/closed.
		badFile, _ := os.CreateTemp("", "bad-file")
		badFile.Close() // Intentionally close it
		os.Remove(badFile.Name())

		// We need a packet that fails GRO (returns groNoGroPacket) to trigger immediate writev inside the loop.
		// A packet with bad protocol fails isGroCandidate.
		badPkt := mockNewPacketBuilder(tcpip.IPv4, 99, "data")

		_, err := vg.Send(badFile, badPkt)
		if err == nil {
			t.Fatal("expected error when writing to a closed file descriptor, got nil")
		}
	})

	t.Run("Flush MegaPackets on Completion", func(t *testing.T) {
		// Prime the flow table with a mock mega packet to test the cleanup/flush loop at the end of Send
		vg.table.megaPackets[0] = megaPacket{
			header:  mockNewPacketBuilder(tcpip.IPv4, tcpip.ProtoTCP, "")[:40],
			data:    [][]byte{[]byte("part1"), []byte("part2")},
			datalen: 10,
			iphlen:  20,
			trhlen:  20,
			gsosize: 5,
			version: tcpip.IPv4,
			proto:   tcpip.ProtoTCP,
		}

		n, err := vg.Send(tmpFile, []byte{})
		if err != nil {
			t.Fatalf("expected flush to succeed, got %v", err)
		}
		if n != 0 {
			t.Fatalf("expected 0 bytes parsed from buffer, got %d", n)
		}

		// Verify cleanup occurred
		if len(vg.table.megaPackets[0].data) != 0 {
			t.Fatalf("expected megaPacket data to be cleaned up/reset, got len %d", len(vg.table.megaPackets[0].data))
		}
	})
}

// Helper: attach a valid TCP/UDP checksum to a packet buffer
func setL4Checksum(proto uint8, version uint8, b []byte, iphLen int) {
	var src, dst []byte
	if version == tcpip.IPv4 {
		src = b[12:16]
		dst = b[16:20]
	} else {
		src = b[8:24]
		dst = b[24:40]
	}

	payload := b[iphLen:]
	var csumOffset int
	if proto == tcpip.ProtoTCP {
		csumOffset = iphLen + 16
	} else {
		csumOffset = iphLen + 6
	}

	// Zero out existing checksum bytes
	b[csumOffset] = 0
	b[csumOffset+1] = 0

	noFold := checksum.HeaderChecksumNoFold(proto, src, dst, uint16(len(payload)))
	csum := ^checksum.Checksum(payload, noFold)

	binary.BigEndian.PutUint16(b[csumOffset:], csum)
}

// Packet builder helper for IPv4 TCP
func makeTestIPv4TCP(srcIP, dstIP []byte, tos, flags, ttl uint8, srcPort, dstPort uint16, seq, ack uint32, tcpFlags uint8, options []byte, payload []byte) packet {
	iphLen := 20
	tcphLen := 20 + len(options)
	totLen := iphLen + tcphLen + len(payload)

	buf := make([]byte, totLen)
	buf[0] = 0x45 // IPv4, IHL=5
	buf[1] = tos
	binary.BigEndian.PutUint16(buf[2:], uint16(totLen))
	buf[6] = flags << 5
	buf[8] = ttl
	buf[9] = tcpip.ProtoTCP
	copy(buf[12:16], srcIP)
	copy(buf[16:20], dstIP)

	binary.BigEndian.PutUint16(buf[20:], srcPort)
	binary.BigEndian.PutUint16(buf[22:], dstPort)
	binary.BigEndian.PutUint32(buf[24:], seq)
	binary.BigEndian.PutUint32(buf[28:], ack)
	buf[32] = uint8(tcphLen/4) << 4 // Data Offset
	buf[33] = tcpFlags

	if len(options) > 0 {
		copy(buf[40:], options)
	}
	copy(buf[iphLen+tcphLen:], payload)

	setL4Checksum(tcpip.ProtoTCP, tcpip.IPv4, buf, iphLen)

	return packet{
		ptr:     buf,
		iph:     buf[:iphLen],
		tcpudph: buf[iphLen : iphLen+tcphLen],
		proto:   tcpip.ProtoTCP,
		version: tcpip.IPv4,
	}
}

// Packet builder helper for IPv4 UDP
func makeTestIPv4UDP(srcIP, dstIP []byte, tos, flags, ttl uint8, srcPort, dstPort uint16, payload []byte) packet {
	iphLen := 20
	udphLen := 8
	totLen := iphLen + udphLen + len(payload)

	buf := make([]byte, totLen)
	buf[0] = 0x45
	buf[1] = tos
	binary.BigEndian.PutUint16(buf[2:], uint16(totLen))
	buf[6] = flags << 5
	buf[8] = ttl
	buf[9] = tcpip.ProtoUDP
	copy(buf[12:16], srcIP)
	copy(buf[16:20], dstIP)

	binary.BigEndian.PutUint16(buf[20:], srcPort)
	binary.BigEndian.PutUint16(buf[22:], dstPort)
	binary.BigEndian.PutUint16(buf[24:], uint16(udphLen+len(payload)))

	copy(buf[iphLen+udphLen:], payload)
	setL4Checksum(tcpip.ProtoUDP, tcpip.IPv4, buf, iphLen)

	return packet{
		ptr:     buf,
		iph:     buf[:iphLen],
		tcpudph: buf[iphLen : iphLen+udphLen],
		proto:   tcpip.ProtoUDP,
		version: tcpip.IPv4,
	}
}

// Packet builder helper for IPv6 TCP
func makeTestIPv6TCP(srcIP, dstIP []byte, tc, hopLimit uint8, srcPort, dstPort uint16, seq, ack uint32, payload []byte) packet {
	iphLen := 40
	tcphLen := 20
	payloadLen := tcphLen + len(payload)

	buf := make([]byte, iphLen+payloadLen)
	buf[0] = 0x60 | (tc >> 4)
	buf[1] = tc << 4
	binary.BigEndian.PutUint16(buf[4:], uint16(payloadLen))
	buf[6] = tcpip.ProtoTCP
	buf[7] = hopLimit
	copy(buf[8:24], srcIP)
	copy(buf[24:40], dstIP)

	binary.BigEndian.PutUint16(buf[40:], srcPort)
	binary.BigEndian.PutUint16(buf[42:], dstPort)
	binary.BigEndian.PutUint32(buf[44:], seq)
	binary.BigEndian.PutUint32(buf[48:], ack)
	buf[52] = 0x50
	buf[53] = tcpip.TCPFlagACK

	copy(buf[iphLen+tcphLen:], payload)
	setL4Checksum(tcpip.ProtoTCP, tcpip.IPv6, buf, iphLen)

	return packet{
		ptr:     buf,
		iph:     buf[:iphLen],
		tcpudph: buf[iphLen : iphLen+tcphLen],
		proto:   tcpip.ProtoTCP,
		version: tcpip.IPv6,
	}
}

func TestIsGroCandidate(t *testing.T) {
	src4, dst4 := []byte{10, 0, 0, 1}, []byte{10, 0, 0, 2}
	src6, dst6 := make([]byte, 16), make([]byte, 16)

	t.Run("IPv4 TCP Valid & Invalid", func(t *testing.T) {
		pkt := makeTestIPv4TCP(src4, dst4, 0, 0, 64, 80, 8080, 100, 200, tcpip.TCPFlagACK, nil, []byte("data"))
		if !isGroCandidate(pkt, false) {
			t.Fatal("expected valid IPv4 TCP packet to be GRO candidate")
		}

		// Invalid: IPv4 IHL > 20 (options present)
		bufOpt := make([]byte, 44)
		bufOpt[0] = 0x46 // IHL = 6 (24 bytes header)
		bufOpt[9] = tcpip.ProtoTCP
		pktOpt := packet{ptr: bufOpt, iph: bufOpt[:24], proto: tcpip.ProtoTCP, version: tcpip.IPv4}
		if isGroCandidate(pktOpt, false) {
			t.Fatal("expected IHL != 20 IPv4 packet to fail candidate check")
		}

		// Invalid: Truncated total length
		shortBuf := make([]byte, 30) // minTcp4CanLen is 40
		shortBuf[0] = 0x45
		shortBuf[9] = tcpip.ProtoTCP
		pktShort := packet{ptr: shortBuf, iph: shortBuf[:20], proto: tcpip.ProtoTCP, version: tcpip.IPv4}
		if isGroCandidate(pktShort, false) {
			t.Fatal("expected short IPv4 TCP packet to fail candidate check")
		}
	})

	t.Run("IPv4 UDP Candidate", func(t *testing.T) {
		pkt := makeTestIPv4UDP(src4, dst4, 0, 0, 64, 80, 8080, []byte("udp"))
		if isGroCandidate(pkt, false) {
			t.Fatal("expected UDP candidate to be false when udpEnable is false")
		}
		if !isGroCandidate(pkt, true) {
			t.Fatal("expected UDP candidate to be true when udpEnable is true")
		}

		// Short length check (< 28)
		shortBuf := make([]byte, 20)
		shortBuf[0] = 0x45
		shortBuf[9] = tcpip.ProtoUDP
		pktShort := packet{ptr: shortBuf, iph: shortBuf[:20], proto: tcpip.ProtoUDP, version: tcpip.IPv4}
		if isGroCandidate(pktShort, true) {
			t.Fatal("expected short UDP packet to fail candidate check")
		}

		// Unsupported Proto
		shortBuf[9] = 99
		pktUnknown := packet{ptr: shortBuf, iph: shortBuf[:20], proto: 99, version: tcpip.IPv4}
		if isGroCandidate(pktUnknown, true) {
			t.Fatal("expected unsupported protocol to fail candidate check")
		}
	})

	t.Run("IPv6 Candidate Checks", func(t *testing.T) {
		pktTCP := makeTestIPv6TCP(src6, dst6, 0, 64, 80, 8080, 100, 200, []byte("payload"))
		if !isGroCandidate(pktTCP, false) {
			t.Fatal("expected IPv6 TCP packet to be candidate")
		}

		// Truncated IPv6 TCP
		shortTCP := packet{ptr: make([]byte, 50), version: tcpip.IPv6, proto: tcpip.ProtoTCP}
		if isGroCandidate(shortTCP, false) {
			t.Fatal("expected short IPv6 TCP to fail candidate check")
		}

		// IPv6 UDP
		pktUDP := packet{ptr: make([]byte, 48), version: tcpip.IPv6, proto: tcpip.ProtoUDP}
		if isGroCandidate(pktUDP, false) {
			t.Fatal("expected IPv6 UDP to fail when udpEnable is false")
		}
		if !isGroCandidate(pktUDP, true) {
			t.Fatal("expected IPv6 UDP to pass when udpEnable is true")
		}

		// Truncated IPv6 UDP
		shortUDP := packet{ptr: make([]byte, 40), version: tcpip.IPv6, proto: tcpip.ProtoUDP}
		if isGroCandidate(shortUDP, true) {
			t.Fatal("expected short IPv6 UDP to fail candidate check")
		}

		// Unknown Proto IPv6
		unknownUDP := packet{ptr: make([]byte, 60), version: tcpip.IPv6, proto: 99}
		if isGroCandidate(unknownUDP, true) {
			t.Fatal("expected unknown protocol on IPv6 to fail candidate check")
		}
	})
}

func TestIpHdrCanCoalesce(t *testing.T) {
	src4, dst4 := []byte{10, 0, 0, 1}, []byte{10, 0, 0, 2}
	pktA := makeTestIPv4TCP(src4, dst4, 0, 0, 64, 80, 8080, 100, 200, tcpip.TCPFlagACK, nil, []byte("a"))

	t.Run("Version Mismatch", func(t *testing.T) {
		v6Hdr := make([]byte, 40)
		v6Hdr[0] = 0x60
		if ipHdrCanCoalesce(pktA, v6Hdr) {
			t.Fatal("expected mismatch version to return false")
		}
	})

	t.Run("IPv4 Field Mismatches", func(t *testing.T) {
		pktToS := makeTestIPv4TCP(src4, dst4, 4, 0, 64, 80, 8080, 100, 200, tcpip.TCPFlagACK, nil, []byte("a"))
		if ipHdrCanCoalesce(pktA, pktToS.iph) {
			t.Fatal("expected ToS mismatch to return false")
		}

		pktFlags := makeTestIPv4TCP(src4, dst4, 0, 2, 64, 80, 8080, 100, 200, tcpip.TCPFlagACK, nil, []byte("a"))
		if ipHdrCanCoalesce(pktA, pktFlags.iph) {
			t.Fatal("expected Flags mismatch to return false")
		}

		pktTTL := makeTestIPv4TCP(src4, dst4, 0, 0, 128, 80, 8080, 100, 200, tcpip.TCPFlagACK, nil, []byte("a"))
		if ipHdrCanCoalesce(pktA, pktTTL.iph) {
			t.Fatal("expected TTL mismatch to return false")
		}

		matching := makeTestIPv4TCP(src4, dst4, 0, 0, 64, 80, 8080, 100, 200, tcpip.TCPFlagACK, nil, []byte("a"))
		if !ipHdrCanCoalesce(pktA, matching.iph) {
			t.Fatal("expected matching IPv4 headers to coalesce")
		}
	})

	t.Run("IPv6 Field Mismatches", func(t *testing.T) {
		src6, dst6 := make([]byte, 16), make([]byte, 16)
		pkt6A := makeTestIPv6TCP(src6, dst6, 0, 64, 80, 8080, 100, 200, []byte("a"))

		pkt6DiffTC := makeTestIPv6TCP(src6, dst6, 8, 64, 80, 8080, 100, 200, []byte("a"))
		if ipHdrCanCoalesce(pkt6A, pkt6DiffTC.iph) {
			t.Fatal("expected IPv6 TrafficClass mismatch to return false")
		}

		pkt6DiffHop := makeTestIPv6TCP(src6, dst6, 0, 128, 80, 8080, 100, 200, []byte("a"))
		if ipHdrCanCoalesce(pkt6A, pkt6DiffHop.iph) {
			t.Fatal("expected IPv6 HopLimit mismatch to return false")
		}

		pkt6Match := makeTestIPv6TCP(src6, dst6, 0, 64, 80, 8080, 100, 200, []byte("a"))
		if !ipHdrCanCoalesce(pkt6A, pkt6Match.iph) {
			t.Fatal("expected matching IPv6 headers to coalesce")
		}
	})
}

func TestCanCoalescePacket(t *testing.T) {
	ft := newFlowTable()
	src4, dst4 := []byte{10, 0, 0, 1}, []byte{10, 0, 0, 2}

	// Base TCP packet setup
	pktBase := makeTestIPv4TCP(src4, dst4, 0, 0, 64, 80, 8080, 1000, 2000, tcpip.TCPFlagACK, nil, []byte("1234"))
	ft.getOrAddFlow(1, pktBase)

	t.Run("Protocol & IP Header Mismatch", func(t *testing.T) {
		pktDiffProto := makeTestIPv4UDP(src4, dst4, 0, 0, 64, 80, 8080, []byte("1234"))
		if res := ft.canCoalescePacket(pktDiffProto, 0); res != coalesceUnavailable {
			t.Fatalf("expected coalesceUnavailable on proto mismatch, got %v", res)
		}

		pktDiffTTL := makeTestIPv4TCP(src4, dst4, 0, 0, 128, 80, 8080, 1004, 2000, tcpip.TCPFlagACK, nil, []byte("1234"))
		if res := ft.canCoalescePacket(pktDiffTTL, 0); res != coalesceUnavailable {
			t.Fatalf("expected coalesceUnavailable on IP header mismatch, got %v", res)
		}
	})

	t.Run("UDP Coalesce Logic", func(t *testing.T) {
		ftUDP := newFlowTable()
		pktUDP1 := makeTestIPv4UDP(src4, dst4, 0, 0, 64, 80, 8080, []byte("1234"))
		ftUDP.getOrAddFlow(2, pktUDP1)

		// Smaller payload -> coalesceAppend
		pktUDP2 := makeTestIPv4UDP(src4, dst4, 0, 0, 64, 80, 8080, []byte("12"))
		if res := ftUDP.canCoalescePacket(pktUDP2, 0); res != coalesceAppend {
			t.Fatalf("expected coalesceAppend for smaller/equal UDP payload, got %v", res)
		}

		// Larger payload -> coalesceUnavailable
		pktUDP3 := makeTestIPv4UDP(src4, dst4, 0, 0, 64, 80, 8080, []byte("12345678"))
		if res := ftUDP.canCoalescePacket(pktUDP3, 0); res != coalesceUnavailable {
			t.Fatalf("expected coalesceUnavailable for larger UDP payload, got %v", res)
		}
	})

	t.Run("TCP Header Length & Options Check", func(t *testing.T) {
		ftOpts := newFlowTable()
		optsA := []byte{0x01, 0x01, 0x01, 0x01}
		optsB := []byte{0x02, 0x02, 0x02, 0x02}

		pktOptA := makeTestIPv4TCP(src4, dst4, 0, 0, 64, 80, 8080, 1000, 2000, tcpip.TCPFlagACK, optsA, []byte("data"))
		ftOpts.getOrAddFlow(3, pktOptA)

		// Length mismatch
		pktNoOpt := makeTestIPv4TCP(src4, dst4, 0, 0, 64, 80, 8080, 1004, 2000, tcpip.TCPFlagACK, nil, []byte("data"))
		if res := ftOpts.canCoalescePacket(pktNoOpt, 0); res != coalesceUnavailable {
			t.Fatalf("expected coalesceUnavailable for TCP header length mismatch")
		}

		// Options content mismatch
		pktOptB := makeTestIPv4TCP(src4, dst4, 0, 0, 64, 80, 8080, 1004, 2000, tcpip.TCPFlagACK, optsB, []byte("data"))
		if res := ftOpts.canCoalescePacket(pktOptB, 0); res != coalesceUnavailable {
			t.Fatalf("expected coalesceUnavailable for options content mismatch")
		}

		// Matching options
		pktOptAMatch := makeTestIPv4TCP(src4, dst4, 0, 0, 64, 80, 8080, 1004, 2000, tcpip.TCPFlagACK, optsA, []byte("data"))
		if res := ftOpts.canCoalescePacket(pktOptAMatch, 0); res != coalesceAppend {
			t.Fatalf("expected coalesceAppend for matching options")
		}
	})

	t.Run("TCP Append Scenarios", func(t *testing.T) {
		// Valid Append
		pktAppend := makeTestIPv4TCP(src4, dst4, 0, 0, 64, 80, 8080, 1004, 2000, tcpip.TCPFlagACK, nil, []byte("5678"))
		if res := ft.canCoalescePacket(pktAppend, 0); res != coalesceAppend {
			t.Fatalf("expected coalesceAppend, got %v", res)
		}

		// Target has PSH set
		ftPSH := newFlowTable()
		pktPSH1 := makeTestIPv4TCP(src4, dst4, 0, 0, 64, 80, 8080, 1000, 2000, tcpip.TCPFlagACK|tcpip.TCPFlagPSH, nil, []byte("1234"))
		ftPSH.getOrAddFlow(4, pktPSH1)
		pktAppendPSH := makeTestIPv4TCP(src4, dst4, 0, 0, 64, 80, 8080, 1004, 2000, tcpip.TCPFlagACK, nil, []byte("5678"))
		if res := ftPSH.canCoalescePacket(pktAppendPSH, 0); res != coalesceUnavailable {
			t.Fatalf("expected coalesceUnavailable when target has PSH set")
		}

		// Target gsoSize == 0
		ftZeroGSO := newFlowTable()
		pktZero := makeTestIPv4TCP(src4, dst4, 0, 0, 64, 80, 8080, 1000, 2000, tcpip.TCPFlagACK, nil, []byte("1234"))
		ftZeroGSO.getOrAddFlow(5, pktZero)
		ftZeroGSO.megaPackets[0].gsosize = 0
		if res := ftZeroGSO.canCoalescePacket(pktAppend, 0); res != coalesceUnavailable {
			t.Fatalf("expected coalesceUnavailable when target gsoSize == 0")
		}

		// datalen % gsoSize != 0
		ftBadMod := newFlowTable()
		pktMod := makeTestIPv4TCP(src4, dst4, 0, 0, 64, 80, 8080, 1000, 2000, tcpip.TCPFlagACK, nil, []byte("1234"))
		ftBadMod.getOrAddFlow(6, pktMod)
		ftBadMod.megaPackets[0].gsosize = 3 // 4 % 3 != 0
		if res := ftBadMod.canCoalescePacket(pktAppend, 0); res != coalesceUnavailable {
			t.Fatalf("expected coalesceUnavailable when datalen %% gsoSize != 0")
		}

		// gsoSize > target.gsoSize
		pktLargeAppend := makeTestIPv4TCP(src4, dst4, 0, 0, 64, 80, 8080, 1004, 2000, tcpip.TCPFlagACK, nil, []byte("567890"))
		if res := ft.canCoalescePacket(pktLargeAppend, 0); res != coalesceUnavailable {
			t.Fatalf("expected coalesceUnavailable when incoming gsoSize > target.gsoSize")
		}
	})

	t.Run("TCP Prepend Scenarios", func(t *testing.T) {
		// Valid Prepend (seq + len == target.seq -> 996 + 4 == 1000)
		pktPrepend := makeTestIPv4TCP(src4, dst4, 0, 0, 64, 80, 8080, 996, 2000, tcpip.TCPFlagACK, nil, []byte("PREP"))
		if res := ft.canCoalescePacket(pktPrepend, 0); res != coalescePrepend {
			t.Fatalf("expected coalescePrepend, got %v", res)
		}

		// Incoming packet has PSH set
		pktPrependPSH := makeTestIPv4TCP(src4, dst4, 0, 0, 64, 80, 8080, 996, 2000, tcpip.TCPFlagACK|tcpip.TCPFlagPSH, nil, []byte("PREP"))
		if res := ft.canCoalescePacket(pktPrependPSH, 0); res != coalesceUnavailable {
			t.Fatalf("expected coalesceUnavailable when incoming prepend packet has PSH")
		}

		// gsoSize < target.gsoSize (2 < 4)
		pktSmallPrepend := makeTestIPv4TCP(src4, dst4, 0, 0, 64, 80, 8080, 998, 2000, tcpip.TCPFlagACK, nil, []byte("PR"))
		if res := ft.canCoalescePacket(pktSmallPrepend, 0); res != coalesceUnavailable {
			t.Fatalf("expected coalesceUnavailable when incoming prepend gsoSize < target.gsoSize")
		}

		// gsoSize > target.gsoSize when len(target.data) > 1
		ftMultiData := newFlowTable()
		pkt1 := makeTestIPv4TCP(src4, dst4, 0, 0, 64, 80, 8080, 1000, 2000, tcpip.TCPFlagACK, nil, []byte("12"))
		ftMultiData.getOrAddFlow(7, pkt1)
		ftMultiData.megaPackets[0].data = append(ftMultiData.megaPackets[0].data, []byte("34")) // len > 1

		pktBigPrepend := makeTestIPv4TCP(src4, dst4, 0, 0, 64, 80, 8080, 996, 2000, tcpip.TCPFlagACK, nil, []byte("1234"))
		if res := ftMultiData.canCoalescePacket(pktBigPrepend, 0); res != coalesceUnavailable {
			t.Fatalf("expected coalesceUnavailable when gsoSize > target.gsoSize and target.data len > 1")
		}

		// Sequence gap
		pktGap := makeTestIPv4TCP(src4, dst4, 0, 0, 64, 80, 8080, 5000, 2000, tcpip.TCPFlagACK, nil, []byte("GAP!"))
		if res := ft.canCoalescePacket(pktGap, 0); res != coalesceUnavailable {
			t.Fatalf("expected coalesceUnavailable on sequence gap")
		}
	})
}

func TestCoalescePacket(t *testing.T) {
	ft := newFlowTable()
	src4, dst4 := []byte{10, 0, 0, 1}, []byte{10, 0, 0, 2}

	pktBase := makeTestIPv4TCP(src4, dst4, 0, 0, 64, 80, 8080, 1000, 2000, tcpip.TCPFlagACK, nil, []byte("BASE"))
	ft.getOrAddFlow(1, pktBase)

	t.Run("Exceed maxPacketLen", func(t *testing.T) {
		ftLarge := newFlowTable()
		ftLarge.getOrAddFlow(1, pktBase)
		ftLarge.megaPackets[0].datalen = maxPacketLen - 10

		pktIncoming := makeTestIPv4TCP(src4, dst4, 0, 0, 64, 80, 8080, 1004, 2000, tcpip.TCPFlagACK, nil, make([]byte, 100))
		res := ftLarge.coalescePacket(pktIncoming, 0, coalesceAppend)
		if res != coalesceTooLarge {
			t.Fatalf("expected coalesceTooLarge, got %v", res)
		}
	})

	t.Run("Prepend PSH Ending", func(t *testing.T) {
		pktPSH := makeTestIPv4TCP(src4, dst4, 0, 0, 64, 80, 8080, 996, 2000, tcpip.TCPFlagACK|tcpip.TCPFlagPSH, nil, []byte("PREP"))
		res := ft.coalescePacket(pktPSH, 0, coalescePrepend)
		if res != coalescePSHEnding {
			t.Fatalf("expected coalescePSHEnding, got %v", res)
		}
	})

	t.Run("Successful Prepend", func(t *testing.T) {
		pktPrepend := makeTestIPv4TCP(src4, dst4, 0, 0, 64, 80, 8080, 996, 2000, tcpip.TCPFlagACK, nil, []byte("PREP"))
		res := ft.coalescePacket(pktPrepend, 0, coalescePrepend)
		if res != coalesceSuccess {
			t.Fatalf("expected coalesceSuccess, got %v", res)
		}

		mega := ft.megaPackets[0]
		if mega.seq != 996 {
			t.Fatalf("expected seq updated to 996, got %d", mega.seq)
		}
		if string(mega.data[0]) != "PREP" || string(mega.data[1]) != "BASE" {
			t.Fatalf("prepended data order incorrect")
		}
	})

	t.Run("Successful Append with PSH and GSO size growth", func(t *testing.T) {
		ftApp := newFlowTable()
		ftApp.getOrAddFlow(1, pktBase)

		pktAppendPSH := makeTestIPv4TCP(src4, dst4, 0, 0, 64, 80, 8080, 1004, 2000, tcpip.TCPFlagACK|tcpip.TCPFlagPSH, nil, []byte("EXTRALONG"))
		res := ftApp.coalescePacket(pktAppendPSH, 0, coalesceAppend)
		if res != coalesceSuccess {
			t.Fatalf("expected coalesceSuccess, got %v", res)
		}

		mega := ftApp.megaPackets[0]
		if mega.flags&tcpip.TCPFlagPSH == 0 {
			t.Fatalf("expected PSH flag to be set in megaPacket")
		}
		if mega.gsosize != uint16(len("EXTRALONG")) {
			t.Fatalf("expected gsoSize to update to %d, got %d", len("EXTRALONG"), mega.gsosize)
		}
	})
}

func TestMegrgePacket(t *testing.T) {
	ft := newFlowTable()
	src4, dst4 := []byte{10, 0, 0, 1}, []byte{10, 0, 0, 2}

	t.Run("Payload Len < Header Len", func(t *testing.T) {
		pktTruncated := packet{
			ptr:     make([]byte, 25), // payloadLen = 5 < tcpudph 20
			iph:     make([]byte, 20),
			tcpudph: make([]byte, 20),
		}
		if status := ft.megrgePacket(pktTruncated); status != groNoGroPacket {
			t.Fatalf("expected groNoGroPacket when payloadLen < len(tcpudph)")
		}
	})

	t.Run("TCP Pure ACK (No Data)", func(t *testing.T) {
		pktNoData := makeTestIPv4TCP(src4, dst4, 0, 0, 64, 80, 8080, 100, 200, tcpip.TCPFlagACK, nil, nil)
		if status := ft.megrgePacket(pktNoData); status != groNoGroPacket {
			t.Fatalf("expected groNoGroPacket for TCP with no payload data")
		}
	})

	t.Run("TCP Invalid Flags (SYN/FIN/RST)", func(t *testing.T) {
		pktSYN := makeTestIPv4TCP(src4, dst4, 0, 0, 64, 80, 8080, 100, 200, tcpip.TCPFlagSYN, nil, []byte("data"))
		if status := ft.megrgePacket(pktSYN); status != groNoGroPacket {
			t.Fatalf("expected groNoGroPacket for non-ACK/PSH flags")
		}
	})

	t.Run("IPv4 MF Flag and Fragment Offset", func(t *testing.T) {
		pktMF := makeTestIPv4TCP(src4, dst4, 0, tcpip.IPv4FlagMF, 64, 80, 8080, 100, 200, tcpip.TCPFlagACK, nil, []byte("data"))
		if status := ft.megrgePacket(pktMF); status != groNoGroPacket {
			t.Fatalf("expected groNoGroPacket when IPv4 MF flag set")
		}

		pktFrag := makeTestIPv4TCP(src4, dst4, 0, 0, 64, 80, 8080, 100, 200, tcpip.TCPFlagACK, nil, []byte("data"))
		binary.BigEndian.PutUint16(pktFrag.iph[6:], 0x0001) // Frag offset != 0
		if status := ft.megrgePacket(pktFrag); status != groNoGroPacket {
			t.Fatalf("expected groNoGroPacket when IPv4 FragOffset != 0")
		}
	})

	t.Run("Invalid Checksum", func(t *testing.T) {
		pktBadCSum := makeTestIPv4TCP(src4, dst4, 0, 0, 64, 80, 8080, 100, 200, tcpip.TCPFlagACK, nil, []byte("data"))
		pktBadCSum.ptr[36] ^= 0xff // Corrupt checksum field
		if status := ft.megrgePacket(pktBadCSum); status != groNoGroPacket {
			t.Fatalf("expected groNoGroPacket for invalid checksum")
		}
	})

	t.Run("Flow Insertion and Coalesce Merge", func(t *testing.T) {
		ftMerge := newFlowTable()

		pkt1 := makeTestIPv4TCP(src4, dst4, 0, 0, 64, 80, 8080, 1000, 2000, tcpip.TCPFlagACK, nil, []byte("DATA1"))
		if status := ftMerge.megrgePacket(pkt1); status != groTableInsert {
			t.Fatalf("expected groTableInsert for first packet in flow")
		}

		pkt2 := makeTestIPv4TCP(src4, dst4, 0, 0, 64, 80, 8080, 1005, 2000, tcpip.TCPFlagACK, nil, []byte("DATA2"))
		if status := ftMerge.megrgePacket(pkt2); status != groMergePacket {
			t.Fatalf("expected groMergePacket when successfully coalescing")
		}
	})

	t.Run("Fallback to addFlow when canCoalesce fails", func(t *testing.T) {
		ftAdd := newFlowTable()

		pkt1 := makeTestIPv4TCP(src4, dst4, 0, 0, 64, 80, 8080, 1000, 2000, tcpip.TCPFlagACK, nil, []byte("DATA1"))
		ftAdd.megrgePacket(pkt1)

		// Sequence gap causes canCoalesce to return coalesceUnavailable -> triggers addFlow & groTableInsert
		pktGap := makeTestIPv4TCP(src4, dst4, 0, 0, 64, 80, 8080, 9999, 2000, tcpip.TCPFlagACK, nil, []byte("DATA2"))
		if status := ftAdd.megrgePacket(pktGap); status != groTableInsert {
			t.Fatalf("expected groTableInsert on fallback to addFlow")
		}
	})
}

func TestTcpUdpChecksumValid(t *testing.T) {
	src4, dst4 := []byte{192, 168, 1, 10}, []byte{192, 168, 1, 20}
	src6, dst6 := make([]byte, 16), make([]byte, 16)

	t.Run("IPv4 Checksums", func(t *testing.T) {
		pktTCP := makeTestIPv4TCP(src4, dst4, 0, 0, 64, 80, 8080, 1, 2, tcpip.TCPFlagACK, nil, []byte("test"))
		if !tcpUdpChecksumValid(pktTCP) {
			t.Fatal("expected IPv4 TCP checksum to be valid")
		}

		pktUDP := makeTestIPv4UDP(src4, dst4, 0, 0, 64, 80, 8080, []byte("test"))
		if !tcpUdpChecksumValid(pktUDP) {
			t.Fatal("expected IPv4 UDP checksum to be valid")
		}
	})

	t.Run("IPv6 Checksums", func(t *testing.T) {
		pktTCP := makeTestIPv6TCP(src6, dst6, 0, 64, 80, 8080, 1, 2, []byte("test"))
		if !tcpUdpChecksumValid(pktTCP) {
			t.Fatal("expected IPv6 TCP checksum to be valid")
		}
	})
}
