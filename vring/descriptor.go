package vring

type descriptorFlag uint16

const (
	descriptorFlagHasNext descriptorFlag = 1 << iota
	descriptorFlagWritable
	descriptorFlagIndirect
)

const descriptorSize = 16

type Descriptor struct {
	address uintptr
	length  uint32
	flags   descriptorFlag
	next    uint16
}
