package vring

const usedElementSize = 8

type UsedElement struct {
	DescriptorIndex uint32
	Length          uint32
}
