package net

import (
	"errors"
	"unsafe"
)

const (
	VirtioNetHdrNeedsCSUM = 0x1
	VirtioNetHdrDataValid = 0x2
	VirtioNetHdrRSCInfo   = 0x4
)

const (
	VirtioNetHdrGsoNone  = 0x0
	VirtioNetHdrGsoTCPV4 = 0x1
	VirtioNetHdrGsoUDP   = 0x3
	VirtioNetHdrGsoTCPV6 = 0x4
	VirtioNetHdrGsoUDPL4 = 0x5
	VirtioNetHdrGsoECN   = 0x80
)

const VirtioNetHdrLen = int(unsafe.Sizeof(VirtioNetHdr{}))

type VirtioNetHdr struct {
	Flags      uint8
	GsoType    uint8
	HdrLen     uint16
	GsoSize    uint16
	CsumStart  uint16
	CsumOffset uint16
	NumBuffers uint16
}

func (v *VirtioNetHdr) Decode(b []byte) error {
	if len(b) < VirtioNetHdrLen {
		return errors.New("short virtio nethdr buffer length")
	}
	copy(unsafe.Slice((*byte)(unsafe.Pointer(v)),
		VirtioNetHdrLen), b[:VirtioNetHdrLen])
	return nil
}

func (v *VirtioNetHdr) Encode(b []byte) error {
	if len(b) < VirtioNetHdrLen {
		return errors.New("short virtio nethdr buffer length")
	}
	copy(b[:VirtioNetHdrLen],
		unsafe.Slice((*byte)(unsafe.Pointer(v)), VirtioNetHdrLen))
	return nil
}
