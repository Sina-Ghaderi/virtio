package vring

import (
	"errors"
	"fmt"
	"math"
	"os"
	"sync"
	"unsafe"

	"golang.org/x/sys/unix"
)

var (
	ErrDescriptorChainEmpty     = errors.New("descriptor chain is empty")
	ErrNotEnoughFreeDescriptors = errors.New("not enough free descriptors")
	ErrInvalidDescriptorChain   = errors.New("invalid descriptor chain")
)

const noFreeHead = uint16(math.MaxUint16)

func descriptorTableSize(queueSize int) int {
	return descriptorSize * queueSize
}

const descriptorTableAlignment = 16

type DescriptorTable struct {
	descriptors   []Descriptor
	freeHeadIndex uint16

	freeNum uint16
	mutex   sync.Mutex
}

func newDescriptorTable(queueSize int, mem []byte) *DescriptorTable {
	dtSize := descriptorTableSize(queueSize)
	if len(mem) != dtSize {
		panic(fmt.Sprintf(
			"memory size (%v) does not match required size "+
				"for descriptor table: %v", len(mem), dtSize))
	}

	return &DescriptorTable{
		descriptors: unsafe.Slice((*Descriptor)(
			unsafe.Pointer(&mem[0])), queueSize),
		freeHeadIndex: noFreeHead,
		freeNum:       0,
	}
}

func (dt *DescriptorTable) Address() uintptr {
	if dt.descriptors == nil {
		panic("descriptor table is not initialized")
	}
	return uintptr(unsafe.Pointer(&dt.descriptors[0]))
}

func (dt *DescriptorTable) BufferAddresses() []uintptr {
	if dt.descriptors == nil {
		panic("descriptor table is not initialized")
	}

	dt.mutex.Lock()
	defer dt.mutex.Unlock()

	ptrs := make([]uintptr, len(dt.descriptors))
	for i, desc := range dt.descriptors {
		ptrs[i] = desc.address
	}

	return ptrs
}

func (dt *DescriptorTable) initializeDescriptors() error {
	pageSize := os.Getpagesize()

	dt.mutex.Lock()
	defer dt.mutex.Unlock()

	for i := range dt.descriptors {

		pagePtr, err := unix.MmapPtr(-1, 0, nil, uintptr(pageSize),
			unix.PROT_READ|unix.PROT_WRITE,
			unix.MAP_PRIVATE|unix.MAP_ANONYMOUS)
		if err != nil {
			return fmt.Errorf(
				"allocate page for descriptor %d: %w", i, err)
		}

		dt.descriptors[i] = Descriptor{
			address: uintptr(pagePtr),
			length:  0,
			flags:   descriptorFlagHasNext,
			next:    uint16((i + 1) % len(dt.descriptors)),
		}
	}

	dt.freeHeadIndex = 0
	dt.freeNum = uint16(len(dt.descriptors))

	return nil
}

func (dt *DescriptorTable) releaseBuffers() error {
	dt.mutex.Lock()
	defer dt.mutex.Unlock()

	var errs []error
	pageSize := os.Getpagesize()
	for i := range dt.descriptors {
		descriptor := &dt.descriptors[i]
		if descriptor.address == 0 {
			continue
		}
		err := unix.MunmapPtr(unsafe.Pointer(descriptor.address), uintptr(pageSize))
		if err == nil {
			descriptor.address = 0
		} else {
			errs = append(errs,
				fmt.Errorf("release page for descriptor %d: %w", i, err))
		}
	}

	dt.freeHeadIndex = noFreeHead
	dt.freeNum = 0

	return errors.Join(errs...)
}

func (dt *DescriptorTable) createDescriptorChain(outBuffers [][]byte, numInBuffers int) (uint16, error) {
	pageSize := os.Getpagesize()
	numDesc := uint16(len(outBuffers) + numInBuffers)

	if numDesc < 1 {
		return 0, ErrDescriptorChainEmpty
	}

	dt.mutex.Lock()
	defer dt.mutex.Unlock()

	if numDesc > dt.freeNum {
		return 0, fmt.Errorf("%w: %d free but needed %d",
			ErrNotEnoughFreeDescriptors, dt.freeNum, numDesc)
	}

	if dt.freeHeadIndex == noFreeHead {
		panic("free descriptor chain head is unset but there should be free descriptors")
	}

	head := dt.descriptors[dt.freeHeadIndex].next
	next := head
	tail := head
	for i, buffer := range outBuffers {
		desc := &dt.descriptors[next]
		checkUnusedDescriptorLength(next, desc)

		if len(buffer) > pageSize {
			panic(fmt.Sprintf(
				"out buffer %d has size %d which exceeds page size %d", i,
				len(buffer), pageSize))
		}

		copy(unsafe.Slice((*byte)(unsafe.Pointer(desc.address)), pageSize), buffer)
		desc.length = uint32(len(buffer))

		desc.flags = descriptorFlagHasNext

		tail = next
		next = desc.next
	}
	for range numInBuffers {
		desc := &dt.descriptors[next]
		checkUnusedDescriptorLength(next, desc)
		desc.length = uint32(pageSize)
		desc.flags = descriptorFlagHasNext | descriptorFlagWritable
		tail = next
		next = desc.next
	}

	tailDesc := &dt.descriptors[tail]
	tailDesc.flags &= ^descriptorFlagHasNext
	tailDesc.next = 0

	dt.freeNum -= numDesc

	if dt.freeNum == 0 {

		if tail != dt.freeHeadIndex {
			panic("descriptor chain takes up all free " +
				"descriptors but does not end with the free chain head")
		}

		dt.freeHeadIndex = noFreeHead
	} else {

		dt.descriptors[dt.freeHeadIndex].next = next
	}

	return head, nil
}

func (dt *DescriptorTable) getDescriptorChain(head uint16) (outBuffers, inBuffers [][]byte, err error) {
	if int(head) > len(dt.descriptors) {
		return nil, nil, fmt.Errorf("%w: index out of range", ErrInvalidDescriptorChain)
	}

	dt.mutex.Lock()
	defer dt.mutex.Unlock()

	next := head
	for range len(dt.descriptors) {
		if next == dt.freeHeadIndex {
			return nil, nil, fmt.Errorf("%w: must not be part of the free chain",
				ErrInvalidDescriptorChain)
		}

		desc := &dt.descriptors[next]

		bs := unsafe.Slice((*byte)(unsafe.Pointer(desc.address)), desc.length)

		if desc.flags&descriptorFlagWritable == 0 {
			outBuffers = append(outBuffers, bs)
		} else {
			inBuffers = append(inBuffers, bs)
		}

		if desc.flags&descriptorFlagHasNext == 0 {
			break
		}

		if desc.next == head {
			return nil, nil, fmt.Errorf("%w: contains a loop",
				ErrInvalidDescriptorChain)
		}

		next = desc.next
	}

	return
}

func (dt *DescriptorTable) freeDescriptorChain(head uint16) error {
	if int(head) > len(dt.descriptors) {
		return fmt.Errorf("%w: index out of range", ErrInvalidDescriptorChain)
	}

	dt.mutex.Lock()
	defer dt.mutex.Unlock()

	next := head
	var tailDesc *Descriptor
	var chainLen uint16
	for range len(dt.descriptors) {
		if next == dt.freeHeadIndex {
			return fmt.Errorf("%w: must not be part of the free chain",
				ErrInvalidDescriptorChain)
		}

		desc := &dt.descriptors[next]
		chainLen++

		desc.length = 0
		desc.flags &= descriptorFlagHasNext

		if desc.flags&descriptorFlagHasNext == 0 {
			tailDesc = desc
			break
		}

		if desc.next == head {
			return fmt.Errorf("%w: contains a loop",
				ErrInvalidDescriptorChain)
		}

		next = desc.next
	}
	if tailDesc == nil {
		panic(fmt.Sprintf(
			"could not find a tail for descriptor chain starting at %d", head))
	}

	tailDesc.flags = descriptorFlagHasNext
	if dt.freeHeadIndex == noFreeHead {

		tailDesc.next = head
		dt.freeHeadIndex = head
	} else {

		freeHeadDesc := &dt.descriptors[dt.freeHeadIndex]
		tailDesc.next = freeHeadDesc.next
		freeHeadDesc.next = head
	}

	dt.freeNum += chainLen
	return nil
}

func checkUnusedDescriptorLength(index uint16, desc *Descriptor) {
	if desc.length != 0 {
		panic(fmt.Sprintf(
			"descriptor %d should be unused but has a non-zero length",
			index),
		)
	}
}
