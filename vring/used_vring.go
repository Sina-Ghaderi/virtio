package vring

import (
	"fmt"
	"sync"
	"unsafe"
)

type usedRingFlag uint16

const (
	usedRingFlagNoNotify usedRingFlag = 1 << iota
)

func usedRingSize(queueSize int) int {
	return 6 + usedElementSize*queueSize
}

const usedRingAlignment = 4

type UsedRing struct {
	initialized    bool
	flags          *usedRingFlag
	ringIndex      *uint16
	ring           []UsedElement
	availableEvent *uint16
	lastIndex      uint16
	mutex          sync.Mutex
}

func newUsedRing(queueSize int, mem []byte) *UsedRing {
	ringSize := usedRingSize(queueSize)
	if len(mem) != ringSize {
		panic(fmt.Sprintf("memory size (%v) does not match required size "+
			"for used ring: %v", len(mem), ringSize))
	}

	ring := unsafe.Slice((*UsedElement)(
		unsafe.Pointer(&mem[4])), queueSize)
	r := UsedRing{
		initialized:    true,
		flags:          (*usedRingFlag)(unsafe.Pointer(&mem[0])),
		ringIndex:      (*uint16)(unsafe.Pointer(&mem[2])),
		ring:           ring,
		availableEvent: (*uint16)(unsafe.Pointer(&mem[ringSize-2])),
	}
	r.lastIndex = *r.ringIndex
	return &r
}

func (r *UsedRing) Address() uintptr {
	if !r.initialized {
		panic("used ring is not initialized")
	}
	return uintptr(unsafe.Pointer(r.flags))
}

func (r *UsedRing) take() []UsedElement {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	ringIndex := *r.ringIndex
	if ringIndex == r.lastIndex {
		return nil
	}

	count := int(ringIndex - r.lastIndex)
	if count < 0 {
		count += 0xffff
	}

	if count > len(r.ring) {
		panic("used ring contains more new elements than the ring is long")
	}

	elems := make([]UsedElement, count)
	for i := range count {
		elems[i] = r.ring[r.lastIndex%uint16(len(r.ring))]
		r.lastIndex++
	}

	return elems
}
