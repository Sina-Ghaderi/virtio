package vhost

import (
	"encoding/binary"
	"fmt"
	"os"
	"unsafe"

	"github.com/sina-ghaderi/virtio/vring"
)

type MemoryRegion struct {
	GuestPhysicalAddress uintptr
	Size                 uint64
	UserspaceAddress     uintptr

	_ uint64
}

type MemoryLayout []MemoryRegion

func NewMemoryLayoutForQueues(queues []*vring.SplitQueue) MemoryLayout {
	pageSize := os.Getpagesize()
	regions := make([]MemoryRegion, 0)
	for _, queue := range queues {
		for _, address := range queue.DescriptorTable().BufferAddresses() {
			regions = append(regions, MemoryRegion{
				GuestPhysicalAddress: address,
				Size:                 uint64(pageSize),
				UserspaceAddress:     address,
			})
		}
	}
	return regions
}

func (regions MemoryLayout) serializePayload() []byte {
	regionCount := len(regions)
	regionSize := int(unsafe.Sizeof(MemoryRegion{}))
	payload := make([]byte, 8+regionCount*regionSize)

	binary.LittleEndian.PutUint32(payload[0:4], uint32(regionCount))

	if regionCount > 0 {
		copied := copy(payload[8:], unsafe.Slice((*byte)(
			unsafe.Pointer(&regions[0])), regionCount*regionSize))
		if copied != regionCount*regionSize {
			panic(fmt.Sprintf(
				"copied only %d bytes of the memory regions, but expected %d",
				copied, regionCount*regionSize),
			)
		}
	}

	return payload
}
