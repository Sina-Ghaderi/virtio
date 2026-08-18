//go:build linux || android

package offload

import (
	"encoding/binary"
	"errors"
	"os"

	"github.com/sina-ghaderi/subpass/internal/checksum"
	"github.com/sina-ghaderi/subpass/internal/virtio"
	"github.com/sina-ghaderi/subpass/tcpip"
)

const maxOffloadSize = virtio.NetHdrLen + maxPacketLen

type VirtioGso struct {
	hdr      virtio.NetHdr
	buff     []byte
	offset   int
	counter  int
	firstSeq uint32
	proto    uint8
	version  uint8
}

var errBuffDrained = errors.New("buffer already drained")

func NewVirtioGso() *VirtioGso {
	buf := make([]byte, 0, maxOffloadSize)
	return &VirtioGso{buff: buf, offset: maxPacketLen}
}

func (p *VirtioGso) Recv(f *os.File, b []byte) (int, error) {

	n, err := p.copyPackets(b)
	if err != errBuffDrained {
		return n, err
	}

	n, err = f.Read(p.buff[:cap(p.buff)])
	if err != nil {
		return 0, err
	}

	if n < virtio.NetHdrLen {
		return 0, errors.New("short read of virtio header")
	}

	p.buff = p.buff[:n]

	if err = p.processGso(); err != nil {
		p.buff = p.buff[:0]
		return 0, err
	}

	n, err = p.copyPackets(b)
	if err != nil {
		return n, err
	}

	return n, err
}

func (p *VirtioGso) copyNonGsoPacket(b []byte) (int, error) {

	start, end := int(p.hdr.CsumStart), int(p.hdr.CsumOffset)
	packet := p.buff[virtio.NetHdrLen:]

	sumFlags := p.hdr.Flags & virtio.VirtioNetHdrNeedsCSUM

	if sumFlags != 0 {
		cSumAt := start + end
		initCsum := uint64(binary.BigEndian.Uint16(packet[cSumAt:]))
		packet[cSumAt], packet[cSumAt+1] = 0, 0
		sum := ^checksum.Checksum(packet[start:], initCsum)
		binary.BigEndian.PutUint16(packet[cSumAt:], sum)
	}

	if len(b) < len(packet) {
		return 0, tcpip.ErrShortBuffer
	}

	p.buff = p.buff[:0]
	return copy(b, packet), nil
}

func (p *VirtioGso) copyPackets(b []byte) (int, error) {

	if len(p.buff) == 0 {
		return 0, errBuffDrained
	}

	if p.hdr.GsoType == virtio.VirtioNetHdrGsoNone {
		return p.copyNonGsoPacket(b)
	} else {
		return p.copyGsoPackets(b)
	}
}

func (p *VirtioGso) copyGsoPackets(b []byte) (int, error) {

	next := p.offset
	packet := p.buff[virtio.NetHdrLen:]
	if next >= len(packet) {
		return 0, errBuffDrained
	}

	const clear = tcpip.TCPFlagFIN | tcpip.TCPFlagPSH
	var srcAddrOffset, addrLen int
	h := p.hdr

	switch p.version {
	case tcpip.IPv4:
		srcAddrOffset = 12
		addrLen = tcpip.IPv4AddrLen
	case tcpip.IPv6:
		srcAddrOffset = 8
		addrLen = tcpip.IPv6AddrLen
	}

	user := b
	byteCopied := 0
	iphlen := int(h.CsumStart)
	gsoSize := int(h.GsoSize)
	index := p.counter

	for ; next < len(packet); index++ {

		endData := min(next+gsoSize, len(packet))
		dataLen := endData - next
		totalLen := int(h.HdrLen) + dataLen

		if len(user) < totalLen {
			p.offset = next
			p.counter = index
			if byteCopied > 0 {
				return byteCopied, nil
			} else {
				return 0, tcpip.ErrShortBuffer
			}
		}

		copy(user[:h.HdrLen], packet)

		if p.version == tcpip.IPv4 {
			if index > 0 {
				id := binary.BigEndian.Uint16(user[4:])
				id += uint16(index)
				binary.BigEndian.PutUint16(user[4:], id)
			}
			binary.BigEndian.PutUint16(user[2:], uint16(totalLen))
			ipv4CSum := ^checksum.Checksum(user[:iphlen], 0)
			binary.BigEndian.PutUint16(user[10:], ipv4CSum)
		} else {
			binary.BigEndian.PutUint16(user[4:], uint16(totalLen-iphlen))
		}

		if p.proto == tcpip.ProtoTCP {

			tcpSeq := p.firstSeq + uint32(gsoSize*index)
			binary.BigEndian.PutUint32(user[iphlen+4:], tcpSeq)
			if endData != len(packet) {
				user[iphlen+13] &^= clear
			}

		} else {
			udphlen := uint16(dataLen) + h.HdrLen - h.CsumStart
			binary.BigEndian.PutUint16(user[iphlen+4:], udphlen)
		}

		copy(user[h.HdrLen:], packet[next:endData])

		tphdrlen := h.HdrLen - h.CsumStart
		lenForPseudo := uint16(dataLen) + tphdrlen
		srcAddr := packet[srcAddrOffset : srcAddrOffset+addrLen]
		dstAddr := packet[srcAddrOffset+addrLen : srcAddrOffset+addrLen*2]

		tpCSumNoFold := checksum.HeaderChecksumNoFold(
			p.proto, srcAddr, dstAddr, lenForPseudo,
		)

		application := user[iphlen:totalLen]
		tpCSum := ^checksum.Checksum(application, tpCSumNoFold)
		tpCsumOffset := h.CsumStart + h.CsumOffset
		binary.BigEndian.PutUint16(user[tpCsumOffset:], tpCSum)

		user = user[totalLen:]
		next = next + gsoSize
		byteCopied += totalLen
	}

	p.offset = next
	p.buff = p.buff[:0]
	p.counter = index
	return byteCopied, nil
}

func (p *VirtioGso) processGso() (err error) {

	var vnethdr virtio.NetHdr
	vnethdr.Decode(p.buff)

	p.offset, p.counter = maxPacketLen, 0
	packet := p.buff[virtio.NetHdrLen:]

	iphlen := int(vnethdr.CsumStart)
	trhlen := int(vnethdr.HdrLen) - int(vnethdr.CsumStart)
	p.hdr = vnethdr

	if len(packet) < 1 {
		return errors.New("short read of virtio packet")
	}

	version := packet[0] >> 4

	switch version {
	case tcpip.IPv4:
		if len(packet) < tcpip.MinIPv4HdrLen {
			return errors.New("short read of virtio ip header")
		}
	case tcpip.IPv6:
		if len(packet) < tcpip.FixIPv6HdrLen {
			return errors.New("short read of virtio ip header")
		}
	default:
		return errors.New("invalid ip header version")
	}

	if vnethdr.GsoType == virtio.VirtioNetHdrGsoNone {
		var total uint16

		if version == tcpip.IPv4 {
			total = binary.BigEndian.Uint16(packet[2:])
		} else {
			total = binary.BigEndian.Uint16(packet[4:]) + tcpip.FixIPv6HdrLen
		}

		if int(total) > len(packet) {
			err = errors.New("short read of virtio ip packet")
		}

		return
	}

	if version == tcpip.IPv4 {
		if iphlen < tcpip.MinIPv4HdrLen || iphlen > tcpip.MaxIPv4HdrLen {
			return errors.New("invalid ipv4 virtio header length")
		}

		if int((packet[0]&0x0f)<<2) != iphlen {
			return errors.New("invalid ipv4 virtio header length")
		}

		packet[10], packet[11] = 0, 0
	} else {
		if iphlen != tcpip.FixIPv6HdrLen {
			return errors.New("invalid ipv6 virtio header length")
		}
	}

	var cSumAt uint16

	switch vnethdr.GsoType {
	case virtio.VirtioNetHdrGsoTCPV4, virtio.VirtioNetHdrGsoTCPV6:

		if vnethdr.GsoType == virtio.VirtioNetHdrGsoTCPV6 &&
			version != tcpip.IPv6 {
			return errors.New("mismatched ipv6 version and gso type")
		}

		if vnethdr.GsoType == virtio.VirtioNetHdrGsoTCPV4 &&
			version != tcpip.IPv4 {
			return errors.New("mismatched ipv4 version and gso type")
		}

		if trhlen < tcpip.MinTCPHdrLen {
			return errors.New("invalid tcp header length")
		}

		if trhlen > tcpip.MaxTCPHdrLen {
			return errors.New("invalid tcp header length")
		}

		if len(packet) < int(vnethdr.HdrLen) {
			return errors.New("short read of virtio ip packet")
		}

		if int((packet[iphlen+12]>>4)<<2) != trhlen {
			return errors.New("invalid tcp header length")
		}

		if vnethdr.CsumOffset != 16 {
			return errors.New("invalid virtio tcp csum_offset")
		}

		if vnethdr.GsoSize == 0 {
			return errors.New("invalid virtio gso size")
		}

		p.proto = tcpip.ProtoTCP
		p.firstSeq = binary.BigEndian.Uint32(packet[iphlen+4:])
		cSumAt = vnethdr.CsumStart + 16

	case virtio.VirtioNetHdrGsoUDPL4:

		if trhlen != tcpip.FixUDPHdrLen {
			return errors.New("invalid udp header length")
		}

		if len(packet) < int(vnethdr.HdrLen) {
			return errors.New("short read of virtio ip packet")
		}

		if vnethdr.CsumOffset != 8 {
			return errors.New("invalid virtio udp csum_offset")
		}

		if vnethdr.GsoSize == 0 {
			return errors.New("invalid virtio gso size")
		}

		p.proto = tcpip.ProtoUDP
		cSumAt = vnethdr.CsumStart + 8

	default:
		return errors.New("unsupported virtio gso type")
	}

	packet[cSumAt], packet[cSumAt+1] = 0, 0

	p.offset = int(vnethdr.HdrLen)
	p.version = version
	return
}
