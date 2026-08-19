package vhost

import (
	"fmt"
	"unsafe"

	"github.com/sina-ghaderi/virtio/net"
	"github.com/sina-ghaderi/virtio/vring"
	"golang.org/x/sys/unix"
)

const (
	vhostIoctlGetFeatures          = 0x8008af00
	vhostIoctlSetFeatures          = 0x4008af00
	vhostIoctlSetOwner             = 0x0000af01
	vhostIoctlSetMemoryLayout      = 0x4008af03
	vhostIoctlSetQueueSize         = 0x4008af10
	vhostIoctlSetQueueAddress      = 0x4028af11
	vhostIoctlSetAvailableRingBase = 0x4008af12
	vhostIoctlSetQueueKickEventFD  = 0x4008af20
	vhostIoctlSetQueueCallEventFD  = 0x4008af21
)

type VRingState struct {
	QueueIndex uint32
	Num        uint32
}

type VRingAddresses struct {
	QueueIndex             uint32
	Flags                  uint32
	DescriptorTableAddress uintptr
	UsedRingAddress        uintptr
	AvailableRingAddress   uintptr
	LogAddress             uintptr
}

// QueueFile is an ioctl request payload that can hold a queue index and a file
// descriptor.
//
// Kernel name: vhost_vring_file
type VRingFile struct {
	QueueIndex uint32
	FD         int32
}

// IoctlPtr is a copy of the similarly named unexported function from the Go
// unix package. This is needed to do custom ioctl requests not supported by the
// standard library.
func IoctlPtr(fd int, req uint, arg unsafe.Pointer) error {
	_, _, err := unix.Syscall(unix.SYS_IOCTL,
		uintptr(fd), uintptr(req), uintptr(arg))
	if err != 0 {
		return fmt.Errorf("ioctl request %d: %w", req, err)
	}
	return nil
}

func GetFeatures(controlFD int) (net.Feature, error) {
	var features net.Feature
	if err := IoctlPtr(controlFD, vhostIoctlGetFeatures,
		unsafe.Pointer(&features)); err != nil {
		return 0, fmt.Errorf("get features: %w", err)
	}
	return features, nil
}

func SetFeatures(controlFD int, features net.Feature) error {
	if err := IoctlPtr(controlFD, vhostIoctlSetFeatures,
		unsafe.Pointer(&features)); err != nil {
		return fmt.Errorf("set features: %w", err)
	}
	return nil
}

func OwnControlFD(controlFD int) error {
	if err := IoctlPtr(controlFD, vhostIoctlSetOwner,
		unsafe.Pointer(nil)); err != nil {
		return fmt.Errorf("set control file descriptor owner: %w", err)
	}
	return nil
}

func SetMemoryLayout(controlFD int, layout MemoryLayout) error {
	payload := layout.serializePayload()
	if err := IoctlPtr(controlFD, vhostIoctlSetMemoryLayout,
		unsafe.Pointer(&payload[0])); err != nil {
		return fmt.Errorf("set memory layout: %w", err)
	}
	return nil
}

func RegisterQueue(controlFD int, queueIndex uint32, queue *vring.SplitQueue) error {
	if err := IoctlPtr(controlFD, vhostIoctlSetQueueSize,
		unsafe.Pointer(&VRingState{
			QueueIndex: queueIndex,
			Num:        uint32(queue.Size()),
		})); err != nil {
		return fmt.Errorf("set vring size: %w", err)
	}

	if err := IoctlPtr(controlFD, vhostIoctlSetQueueAddress,
		unsafe.Pointer(&VRingAddresses{
			QueueIndex:             queueIndex,
			Flags:                  0,
			DescriptorTableAddress: queue.DescriptorTable().Address(),
			UsedRingAddress:        queue.UsedRing().Address(),
			AvailableRingAddress:   queue.AvailableRing().Address(),
			LogAddress:             0,
		})); err != nil {
		return fmt.Errorf("set vring addresses: %w", err)
	}

	if err := IoctlPtr(controlFD,
		vhostIoctlSetAvailableRingBase, unsafe.Pointer(&VRingState{
			QueueIndex: queueIndex,
			Num:        0,
		})); err != nil {
		return fmt.Errorf("set available ring base: %w", err)
	}

	if err := IoctlPtr(controlFD, vhostIoctlSetQueueKickEventFD,
		unsafe.Pointer(&VRingFile{
			QueueIndex: queueIndex,
			FD:         int32(queue.KickEventFD()),
		})); err != nil {
		return fmt.Errorf("set kick event file descriptor: %w", err)
	}

	if err := IoctlPtr(controlFD, vhostIoctlSetQueueCallEventFD,
		unsafe.Pointer(&VRingFile{
			QueueIndex: queueIndex,
			FD:         int32(queue.CallEventFD()),
		})); err != nil {
		return fmt.Errorf("set call event file descriptor: %w", err)
	}

	return nil
}
