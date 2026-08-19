package vring

import (
	"fmt"
	"sync"
	"unsafe"
)

type availableRingFlag uint16

const availableRingAlignment = 2
const (
	availableRingFlagNoInterrupt availableRingFlag = 1 << iota
)

func availableRingSize(queueSize int) int {
	return 6 + 2*queueSize
}

type AvailableRing struct {
	initialized bool
	flags       *availableRingFlag
	ringIndex   *uint16
	ring        []uint16
	usedEvent   *uint16
	mutex       sync.Mutex
}

func newAvailableRing(queueSize int, mem []byte) *AvailableRing {
	ringSize := availableRingSize(queueSize)
	if len(mem) != ringSize {
		panic(fmt.Sprintf(
			"memory size (%v) does not match required size "+
				"for available ring: %v", len(mem), ringSize))
	}

	ring := unsafe.Slice((*uint16)(unsafe.Pointer(&mem[4])),
		queueSize)

	return &AvailableRing{
		initialized: true,
		flags:       (*availableRingFlag)(unsafe.Pointer(&mem[0])),
		ringIndex:   (*uint16)(unsafe.Pointer(&mem[2])),
		ring:        ring,
		usedEvent:   (*uint16)(unsafe.Pointer(&mem[ringSize-2])),
	}
}

func (r *AvailableRing) Address() uintptr {
	if !r.initialized {
		panic("available ring is not initialized")
	}
	return uintptr(unsafe.Pointer(r.flags))
}

func (r *AvailableRing) offer(chainHeads []uint16) {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	for offset, head := range chainHeads {
		insertIndex := int(*r.ringIndex+uint16(offset)) % len(r.ring)
		r.ring[insertIndex] = head
	}
	*r.ringIndex += uint16(len(chainHeads))
}
