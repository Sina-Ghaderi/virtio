//go:build linux || android

package offload

import (
	"bytes"
	"encoding/binary"
	"os"

	"github.com/sina-ghaderi/subpass/internal/checksum"
	"github.com/sina-ghaderi/subpass/internal/virtio"

	"github.com/sina-ghaderi/subpass/tcpip"
)

type groStatus int
type canCoalesce int
type coalesceResult int

const maxPacketLen = int(^uint16(0))
const batchProcess = 1 << 7

const (
	coalesceTooLarge coalesceResult = iota
	coalescePSHEnding
	coalesceItemInvalidCsum
	coalescePktInvalidCsum
	coalesceSuccess
)

const (
	coalescePrepend canCoalesce = iota - 1
	coalesceUnavailable
	coalesceAppend
)
const (
	groNoGroPacket groStatus = iota
	groTableInsert
	groMergePacket
)

type VirtioGro struct {
	table        *flowTable
	udpSupported bool
}

type packet struct {
	ptr     []byte
	iph     []byte
	tcpudph []byte
	proto   uint8
	version uint8
}

type packetID uint64
type flowInfo []packetID

type megaPacket struct {
	header  []byte
	data    [][]byte
	datalen int
	seq     uint32
	gsosize uint16
	flags   uint16
	iphlen  uint8
	trhlen  uint8
	proto   uint8
	version uint8
}

type flowTable struct {
	ht          map[uint64]flowInfo
	flowPool    []flowInfo
	megaPackets []megaPacket
	buffPos     int
}

func NewVirtioGro(udpSupport bool) *VirtioGro {
	g := new(VirtioGro)
	g.table = newFlowTable()
	g.udpSupported = udpSupport
	return g

}

func newFlowTable() *flowTable {

	t := new(flowTable)
	t.ht = make(map[uint64]flowInfo, batchProcess)
	t.megaPackets = make([]megaPacket, batchProcess)
	t.flowPool = make([]flowInfo, batchProcess)

	for i := range t.flowPool {
		t.flowPool[i] = make(flowInfo, 0, batchProcess)
	}

	for i := range t.megaPackets {
		t.megaPackets[i] = megaPacket{
			data: make([][]byte, 0, batchProcess),
		}
	}

	return t
}

func (t *flowTable) newFlowInfo() flowInfo {

	if len(t.flowPool) == 0 {
		t.flowPool = make([]flowInfo, batchProcess)
		for i := range t.flowPool {
			t.flowPool[i] = make(flowInfo, 0, batchProcess)
		}
	}

	flow := t.flowPool[len(t.flowPool)-1]
	t.flowPool = t.flowPool[:len(t.flowPool)-1]
	return flow
}

func (t *flowTable) growMegaPackets() {

	if t.buffPos < len(t.megaPackets) {
		return
	}

	c := megaPacket{data: make([][]byte, 0, batchProcess)}
	t.megaPackets = append(t.megaPackets, c)
}

func (t *flowTable) getOrAddFlow(key uint64, p packet) flowInfo {

	if flow, ok := t.ht[key]; ok {
		return flow
	}

	t.growMegaPackets()

	data := p.ptr[len(p.iph)+len(p.tcpudph):]
	mega := t.megaPackets[t.buffPos]
	mega.datalen = len(data)
	mega.data = append(mega.data, data)

	mega.header = p.ptr[:len(p.iph)+len(p.tcpudph)]

	mega.iphlen = uint8(len(p.iph))
	mega.trhlen = uint8(len(p.tcpudph))
	mega.gsosize = uint16(len(data))
	mega.proto = p.proto
	mega.version = p.version

	if p.proto == tcpip.ProtoTCP {
		tcp := tcpip.TCPHeader(p.tcpudph)
		mega.seq = tcp.Seq()
		mega.flags = tcp.Flags()
	}

	t.megaPackets[t.buffPos] = mega
	t.ht[key] = append(t.newFlowInfo(), packetID(t.buffPos))
	t.buffPos = t.buffPos + 1
	return nil
}

func (t *flowTable) addFlow(key uint64, p packet) {

	flow, ok := t.ht[key]
	if !ok {
		flow = t.newFlowInfo()
	}

	t.growMegaPackets()

	data := p.ptr[len(p.iph)+len(p.tcpudph):]
	mega := t.megaPackets[t.buffPos]
	mega.datalen = len(data)
	mega.data = append(mega.data, data)
	mega.header = p.ptr[:len(p.iph)+len(p.tcpudph)]

	mega.iphlen = uint8(len(p.iph))
	mega.trhlen = uint8(len(p.tcpudph))
	mega.gsosize = uint16(len(data))
	mega.proto = p.proto
	mega.version = p.version

	if p.proto == tcpip.ProtoTCP {
		tcp := tcpip.TCPHeader(p.tcpudph)
		mega.seq = tcp.Seq()
		mega.flags = tcp.Flags()
	}

	t.megaPackets[t.buffPos] = mega
	t.ht[key] = append(flow, packetID(t.buffPos))
	t.buffPos = t.buffPos + 1
}

func (t *flowTable) resetFlowTable() {

	for _, flow := range t.ht {
		if len(t.flowPool) >= batchProcess {
			break
		}
		flow = flow[:0]
		t.flowPool = append(t.flowPool, flow)
	}

	clear(t.ht)
	t.buffPos = 0
}

func newPacket(b []byte) (p packet, err error) {

	p.version, err = tcpip.Version(b)
	if err != nil {
		return p, err
	}

	var pktLen uint16

	if p.version == tcpip.IPv4 {
		iphdr, err := tcpip.NewIPv4Header(b)
		if err != nil {
			return p, err
		}

		p.iph = b[:iphdr.HdrLen()]
		p.proto = iphdr.Protocol()
		pktLen = iphdr.TotalLen()

	} else {
		iphdr, err := tcpip.NewIPv6Header(b)
		if err != nil {
			return p, err
		}

		p.iph = b[:tcpip.FixIPv6HdrLen]
		p.proto = iphdr.NextHeader()
		pktLen = iphdr.PayloadLen() + tcpip.FixIPv6HdrLen
	}

	p.ptr = b[:pktLen]
	tcpUdpSegment := b[len(p.iph):pktLen]

	switch p.proto {
	case tcpip.ProtoTCP:
		tcp, err := tcpip.NewTCPHeader(tcpUdpSegment)
		if err != nil {
			return p, err
		}

		p.tcpudph = tcpUdpSegment[:tcp.HdrLen()]

	case tcpip.ProtoUDP:
		_, err := tcpip.NewUDPHeader(tcpUdpSegment)
		if err != nil {
			return p, err
		}

		p.tcpudph = tcpUdpSegment[:tcpip.FixUDPHdrLen]
	}

	return p, nil
}

func isGroCandidate(packet packet, udpEnable bool) bool {

	const minTcp4CanLen = tcpip.MinIPv4HdrLen + tcpip.MinTCPHdrLen
	const minUdp4CanLen = tcpip.MinIPv4HdrLen + tcpip.FixUDPHdrLen
	const minTcp6CanLen = tcpip.FixIPv6HdrLen + tcpip.MinTCPHdrLen
	const minUdp6CanLen = tcpip.FixIPv6HdrLen + tcpip.FixUDPHdrLen

	totalLen := len(packet.ptr)

	if packet.version == tcpip.IPv4 {
		iphLen := tcpip.IPv4Header(packet.iph).HdrLen()
		switch {
		case iphLen != tcpip.MinIPv4HdrLen:
			return false
		case packet.proto == tcpip.ProtoTCP && totalLen >= minTcp4CanLen:
			return true
		case !udpEnable:
			return false
		case packet.proto == tcpip.ProtoUDP && totalLen >= minUdp4CanLen:
			return true
		}
		return false
	}

	switch {
	case packet.proto == tcpip.ProtoTCP && totalLen >= minTcp6CanLen:
		return true
	case !udpEnable:
		return false
	case packet.proto == tcpip.ProtoUDP && totalLen >= minUdp6CanLen:
		return true
	}
	return false
}

func ipHdrCanCoalesce(ipa packet, ipb []byte) bool {

	vb := ipb[0] >> 4
	if vb != ipa.version {
		return false
	}

	if vb == tcpip.IPv4 {
		ipah := tcpip.IPv4Header(ipa.iph)
		ipbh := tcpip.IPv4Header(ipb)

		switch {
		case ipah.ToS() != ipbh.ToS():
			return false
		case ipah.Flags() != ipbh.Flags():
			return false
		case ipah.TTL() != ipbh.TTL():
			return false
		}
		return true
	}

	ipah := tcpip.IPv6Header(ipa.iph)
	ipbh := tcpip.IPv6Header(ipb)

	if ipah.TrafficClass() != ipbh.TrafficClass() ||
		ipah.HopLimit() != ipbh.HopLimit() {
		return false
	}
	return true
}

func (t *flowTable) canCoalescePacket(pkt packet, info packetID) canCoalesce {

	target := t.megaPackets[info]

	if pkt.proto != target.proto {
		return coalesceUnavailable
	}

	if !ipHdrCanCoalesce(pkt, target.header) {
		return coalesceUnavailable
	}

	gsoSize := len(pkt.ptr) - (len(pkt.iph) + len(pkt.tcpudph))

	if pkt.proto == tcpip.ProtoUDP {
		if gsoSize > int(target.gsosize) {
			return coalesceUnavailable
		}
		return coalesceAppend
	}

	tcph := tcpip.TCPHeader(pkt.tcpudph)
	if len(pkt.tcpudph) != int(target.trhlen) {
		return coalesceUnavailable
	}

	if len(pkt.tcpudph) > tcpip.MinTCPHdrLen {

		optOffset := len(pkt.iph) + tcpip.MinTCPHdrLen
		optEndsAt := len(pkt.iph) + len(pkt.tcpudph)
		opt1 := pkt.ptr[optOffset:optEndsAt]
		optOffset = int(target.iphlen) + tcpip.MinTCPHdrLen
		optEndsAt = int(target.iphlen) + int(target.trhlen)
		hdr := target.header[optOffset:optEndsAt]
		if !bytes.Equal(opt1, hdr) {
			return coalesceUnavailable
		}
	}

	switch {
	case tcph.Seq() == target.seq+uint32(target.datalen):
		if target.flags&tcpip.TCPFlagPSH == tcpip.TCPFlagPSH {
			return coalesceUnavailable
		}

		if target.gsosize == 0 ||
			target.datalen%int(target.gsosize) != 0 {
			return coalesceUnavailable
		}

		if gsoSize > int(target.gsosize) {
			return coalesceUnavailable
		}
		return coalesceAppend

	case tcph.Seq()+uint32(gsoSize) == target.seq:

		if tcph.Flags()&tcpip.TCPFlagPSH == tcpip.TCPFlagPSH {
			return coalesceUnavailable
		}

		if gsoSize < int(target.gsosize) {
			return coalesceUnavailable
		}

		if gsoSize > int(target.gsosize) && len(target.data) > 1 {
			return coalesceUnavailable
		}

		return coalescePrepend
	}

	return coalesceUnavailable
}

func (t *flowTable) megrgePacket(pkt packet) groStatus {

	payloadLen := len(pkt.ptr) - len(pkt.iph)

	if payloadLen < len(pkt.tcpudph) {
		return groNoGroPacket
	}

	if pkt.proto == tcpip.ProtoTCP &&
		payloadLen == len(pkt.tcpudph) {
		return groNoGroPacket
	}

	if pkt.proto == tcpip.ProtoTCP {
		flags := tcpip.TCPHeader(pkt.tcpudph).Flags()
		if flags != tcpip.TCPFlagACK {
			if flags != tcpip.TCPFlagACK|tcpip.TCPFlagPSH {
				return groNoGroPacket
			}
		}
	}

	if pkt.version == tcpip.IPv4 {
		iph := tcpip.IPv4Header(pkt.iph)
		switch {
		case iph.Flags()&tcpip.IPv4FlagMF != 0:
			return groNoGroPacket
		case iph.FragOffset() != 0:
			return groNoGroPacket
		}
	}

	if !tcpUdpChecksumValid(pkt) {
		return groNoGroPacket
	}

	flowkey := fastFlowHash(pkt)
	flowPackets := t.getOrAddFlow(flowkey, pkt)
	if flowPackets == nil {
		return groTableInsert
	}

	for i := len(flowPackets) - 1; i >= 0; i-- {
		flowPacketID := flowPackets[i]
		mode := t.canCoalescePacket(pkt, flowPacketID)
		if mode == coalesceUnavailable {
			continue
		}

		stat := t.coalescePacket(pkt, flowPacketID, mode)
		if stat == coalesceSuccess {
			return groMergePacket
		}
	}

	t.addFlow(flowkey, pkt)
	return groTableInsert
}

func (t *flowTable) coalescePacket(pkt packet, id packetID, mode canCoalesce) coalesceResult {

	target := t.megaPackets[id]
	hdrLen := len(pkt.iph) + len(pkt.tcpudph)

	if target.datalen+len(pkt.ptr) > maxPacketLen {
		return coalesceTooLarge
	}

	tcph := tcpip.TCPHeader(pkt.tcpudph)
	if mode == coalescePrepend {
		if tcph.FlagIsSet(tcpip.TCPFlagPSH) {
			return coalescePSHEnding
		}

		target.seq = tcph.Seq()
		target.header = pkt.ptr[:hdrLen]
		target.data = append(target.data, nil)
		copy(target.data[1:], target.data)
		target.data[0] = pkt.ptr[hdrLen:]
		target.datalen += len(target.data[0])

	} else {
		if pkt.proto == tcpip.ProtoTCP && tcph.FlagIsSet(tcpip.TCPFlagPSH) {
			target.flags |= tcpip.TCPFlagPSH
		}

		payload := pkt.ptr[hdrLen:]
		target.data = append(target.data, payload)
		target.datalen += len(payload)
	}

	gsoSize := len(pkt.ptr[hdrLen:])
	if gsoSize > int(target.gsosize) {
		target.gsosize = uint16(gsoSize)
	}

	t.megaPackets[id] = target
	return coalesceSuccess
}

func (p *VirtioGro) Send(f *os.File, b []byte) (n int, err error) {

	const maxHdrLen = virtio.NetHdrLen +
		tcpip.MaxIPv4HdrLen + tcpip.MaxTCPHdrLen

	unchecked := b
	hdrbuf := make([]byte, maxHdrLen)
	vnthdr := hdrbuf[:virtio.NetHdrLen]

	defer p.table.resetFlowTable()

	var packet packet

	for len(unchecked) > 0 {
		packet, err = newPacket(unchecked)
		if err != nil {
			break
		}

		unchecked = unchecked[len(packet.ptr):]

		if p.prosessGro(packet) != groNoGroPacket {

			continue
		}

		clear(hdrbuf)
		hdrLen := len(packet.iph) + len(packet.tcpudph)
		phdrs := packet.ptr[:hdrLen]
		pdata := packet.ptr[hdrLen:]

		err = writeVector(f, vnthdr, phdrs, len(pdata), [][]byte{pdata})
		if err != nil {
			break
		}
	}

	if err == tcpip.ErrShortBuffer && len(unchecked) < len(b) {
		err = nil
	}

	for i, mega := range p.table.megaPackets {

		if mega.header == nil {
			break
		}

		if err == nil {
			h := p.table.prepareMegaPacket(mega, hdrbuf)
			err = writeVector(f, vnthdr, h, mega.datalen, mega.data)
		}

		// cleanup
		clean := megaPacket{data: mega.data[:0]}
		p.table.megaPackets[i] = clean
	}

	if err != nil {
		return n, err
	}

	if len(unchecked) != 0 {
		n = len(b) - len(unchecked)
	} else {
		n = len(b)
	}

	return n, err
}

func (t *flowTable) prepareMegaPacket(mega megaPacket, buf []byte) []byte {

	const nethdrLen = virtio.NetHdrLen

	hdr := buf[:nethdrLen]
	header := buf[nethdrLen : nethdrLen+len(mega.header)]

	if len(mega.data) < 2 {
		clear(hdr)
		return mega.header
	}

	hdrInfo := &virtio.NetHdr{
		Flags:      virtio.VirtioNetHdrNeedsCSUM,
		HdrLen:     uint16(mega.iphlen + mega.trhlen),
		GsoSize:    mega.gsosize,
		CsumStart:  uint16(mega.iphlen),
		CsumOffset: 16,
	}

	copy(header, mega.header)

	var src, dst []byte

	switch mega.version {
	case tcpip.IPv6:
		hdrInfo.GsoType = virtio.VirtioNetHdrGsoTCPV6

		iph := tcpip.IPv6Header(header)
		payloadLen := mega.datalen + len(header) - int(mega.iphlen)
		iph.SetPayloadLen(uint16(payloadLen))
		src = iph.SrcAddr()
		dst = iph.DstAddr()

	case tcpip.IPv4:
		hdrInfo.GsoType = virtio.VirtioNetHdrGsoTCPV4
		iph := tcpip.IPv4Header(header)
		iph.SetChecksum(0)
		totalLen := mega.datalen + len(header)
		iph.SetTotalLen(uint16(totalLen))
		iphCSum := ^checksum.Checksum(header[:mega.iphlen], 0)
		iph.SetChecksum(iphCSum)
		src = iph.SrcAddr()
		dst = iph.DstAddr()
	}

	segment := header[mega.iphlen:]
	slen := uint16(len(segment))

	if mega.proto == tcpip.ProtoTCP {

		tcph := tcpip.TCPHeader(segment)
		tcph.SetFlags(mega.flags)
		psum := checksum.HeaderChecksumNoFold(mega.proto, src, dst, slen)
		tcph.SetChecksum(checksum.Checksum(nil, psum))

	} else {
		hdrInfo.CsumOffset = 6
		hdrInfo.GsoType = virtio.VirtioNetHdrGsoUDPL4
		psum := checksum.HeaderChecksumNoFold(mega.proto, src, dst, slen)
		udph := tcpip.UDPHeader(segment)
		udph.SetChecksum(checksum.Checksum(nil, psum))
	}

	hdrInfo.Encode(hdr)
	return header
}

func (p *VirtioGro) prosessGro(packet packet) groStatus {

	if !isGroCandidate(packet, p.udpSupported) {
		return groNoGroPacket
	}

	return p.table.megrgePacket(packet)
}

func tcpUdpChecksumValid(pkt packet) bool {
	var src, dst []byte
	switch pkt.version {
	case tcpip.IPv4:
		iph := tcpip.IPv4Header(pkt.iph)
		src = iph.SrcAddr()
		dst = iph.DstAddr()
	case tcpip.IPv6:
		iph := tcpip.IPv6Header(pkt.iph)
		src = iph.SrcAddr()
		dst = iph.DstAddr()
	}

	payload := pkt.ptr[len(pkt.iph):]
	cSum := checksum.HeaderChecksumNoFold(pkt.proto, src, dst, uint16(len(payload)))
	return ^checksum.Checksum(payload, cSum) == 0
}

func fastFlowHash(p packet) uint64 {
	hash := uint64(14695981039346656037)
	const prime uint64 = 1099511628211

	var sp, dp uint16

	tcp := tcpip.TCPHeader(p.tcpudph)
	udp := tcpip.UDPHeader(p.tcpudph)

	if p.proto == tcpip.ProtoTCP {
		sp, dp = tcp.SrcPort(), tcp.DstPort()
	} else {
		sp, dp = udp.SrcPort(), udp.DstPort()
	}

	tuple := uint64(p.proto) | (uint64(sp) << 8) | (uint64(dp) << 24)
	hash ^= tuple
	hash *= prime

	if p.proto == tcpip.ProtoTCP {
		hash ^= uint64(tcp.Ack())
		hash *= prime
	}

	ipv4 := tcpip.IPv4Header(p.iph)
	ipv6 := tcpip.IPv6Header(p.iph)
	var src, dst []byte

	if p.version == tcpip.IPv6 {
		src, dst = ipv6.SrcAddr(), ipv6.DstAddr()
		hash ^= binary.LittleEndian.Uint64(src[0:8])
		hash *= prime
		hash ^= binary.LittleEndian.Uint64(src[8:16])
		hash *= prime

		hash ^= binary.LittleEndian.Uint64(dst[0:8])
		hash *= prime
		hash ^= binary.LittleEndian.Uint64(dst[8:16])
		hash *= prime
	} else {
		src, dst = ipv4.SrcAddr(), ipv4.DstAddr()
		hash ^= uint64(binary.LittleEndian.Uint32(src[0:4]))
		hash *= prime

		hash ^= uint64(binary.LittleEndian.Uint32(dst[0:4]))
		hash *= prime
	}

	return hash
}
