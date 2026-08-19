package vhostnet

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"unsafe"

	"github.com/sina-ghaderi/virtio/net"
	"github.com/sina-ghaderi/virtio/vhost"
	"github.com/sina-ghaderi/virtio/vring"
	"golang.org/x/sys/unix"
)

const vhostModulePath = "/dev/vhost-net"
const vhostOpenMode = os.O_RDWR | os.O_EXCL

const (
	vhostNetIoctlSetBackend = 0x4008af30
)

var ErrDeviceClosed = errors.New("device was closed")

const (
	receiveQueueIndex  = 0
	transmitQueueIndex = 1
)

type Device struct {
	initialized   bool
	controlFD     int
	receiveQueue  *vring.SplitQueue
	transmitQueue *vring.SplitQueue
	transmitted   []chan vring.UsedElement
}

func NewDevice(backend *os.File, vringSize int) (*Device, error) {

	if vringSize == 0 {
		vringSize = 4096
	}

	err := vring.CheckVRingSize(vringSize)
	if err != nil {
		return nil, err
	}

	if backend == nil {
		return nil, errors.New("invalid backend file descriptor")
	}

	dev := Device{controlFD: -1}

	defer func() {
		if err != nil {
			dev.Close()
		}
	}()

	dev.controlFD, err = unix.Open(vhostModulePath, vhostOpenMode, 0666)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", vhostModulePath, err)
	}

	if err = vhost.OwnControlFD(dev.controlFD); err != nil {
		return nil, err
	}

	features := net.FeatureVersion1 | net.FeatureNetMergeRXBuffers
	if err = vhost.SetFeatures(dev.controlFD, features); err != nil {
		return nil, err
	}

	if dev.receiveQueue, err = createQueue(dev.controlFD,
		receiveQueueIndex, vringSize); err != nil {
		return nil, fmt.Errorf("create receive queue: %w", err)
	}
	if dev.transmitQueue, err = createQueue(dev.controlFD,
		transmitQueueIndex, vringSize); err != nil {
		return nil, fmt.Errorf("create transmit queue: %w", err)
	}

	memoryLayout := vhost.NewMemoryLayoutForQueues(
		[]*vring.SplitQueue{dev.receiveQueue, dev.transmitQueue},
	)

	if err = vhost.SetMemoryLayout(dev.controlFD, memoryLayout); err != nil {
		return nil, err
	}

	if err = SetQueueBackend(dev.controlFD, receiveQueueIndex, int(backend.Fd())); err != nil {
		return nil, fmt.Errorf("set receive queue backend: %w", err)
	}
	if err = SetQueueBackend(dev.controlFD, transmitQueueIndex, int(backend.Fd())); err != nil {
		return nil, fmt.Errorf("set transmit queue backend: %w", err)
	}

	if err = dev.refillReceiveQueue(); err != nil {
		return nil, fmt.Errorf("refill receive queue: %w", err)
	}

	dev.transmitted = make([]chan vring.UsedElement, dev.transmitQueue.Size())
	for i := range len(dev.transmitted) {
		dev.transmitted[i] = make(chan vring.UsedElement, 1)
	}

	go dev.monitorTransmitQueue()
	devPtr := &dev
	runtime.SetFinalizer(devPtr, (*Device).Close)
	return devPtr, nil
}

func (dev *Device) monitorTransmitQueue() {
	usedChan := dev.transmitQueue.UsedDescriptorChains()
	for {
		used, ok := <-usedChan
		if !ok {
			return
		}
		if int(used.DescriptorIndex) > len(dev.transmitted) {
			panic(fmt.Sprintf(
				"device provided a used descriptor index (%d) that is out of range",
				used.DescriptorIndex))
		}
		dev.transmitted[used.DescriptorIndex] <- used
	}
}

func (dev *Device) TransmitPacket(vnethdr net.VirtioNetHdr, packet []byte) error {

	dev.ensureInitialized()
	vnethdrBuf := make([]byte, net.VirtioNetHdrLen)
	if err := vnethdr.Encode(vnethdrBuf); err != nil {
		return err
	}

	outBuffers := [][]byte{vnethdrBuf, packet}
	chainIndex, err := dev.transmitQueue.OfferDescriptorChain(outBuffers, 0, true)
	if err != nil {
		return fmt.Errorf("offer descriptor chain: %w", err)
	}

	<-dev.transmitted[chainIndex]
	if err = dev.transmitQueue.FreeDescriptorChain(chainIndex); err != nil {
		return fmt.Errorf("free descriptor chain: %w", err)
	}

	return nil
}

func (dev *Device) ReceivePacket() (net.VirtioNetHdr, []byte, error) {
	var (
		chainHeads []uint16

		vnethdr net.VirtioNetHdr
		buffers [][]byte

		packetLength = -net.VirtioNetHdrLen
	)

	dev.ensureInitialized()

	for remainingChains := 1; remainingChains > 0; remainingChains-- {
		// Get the next descriptor chain.
		usedElement, ok := <-dev.receiveQueue.UsedDescriptorChains()
		if !ok {
			return net.VirtioNetHdr{}, nil, ErrDeviceClosed
		}

		// Track this chain to be freed later.
		head := uint16(usedElement.DescriptorIndex)
		chainHeads = append(chainHeads, head)

		outBuffers, inBuffers, err := dev.receiveQueue.GetDescriptorChain(head)
		if err != nil {
			return net.VirtioNetHdr{},
				nil, fmt.Errorf("get descriptor chain: %w", err)
		}
		if len(outBuffers) > 0 {
			panic("receive queue contains device-readable buffers")
		}
		if len(inBuffers) == 0 {
			panic("descriptor chain contains no buffers")
		}

		inBuffers = truncateBuffers(inBuffers, int(usedElement.Length))
		packetLength += int(usedElement.Length)
		if len(buffers) == 0 {
			if err = vnethdr.Decode(inBuffers[0]); err != nil {
				return net.VirtioNetHdr{}, nil, err
			}

			inBuffers[0] = inBuffers[0][net.VirtioNetHdrLen:]
			remainingChains = int(vnethdr.NumBuffers)
		}

		buffers = append(buffers, inBuffers...)
	}

	packet := make([]byte, packetLength)
	copied := 0
	for _, buffer := range buffers {
		copied += copy(packet[copied:], buffer)
	}

	if copied != packetLength {
		panic(fmt.Sprintf(
			"expected to copy %d bytes but only copied %d bytes",
			packetLength, copied),
		)
	}

	for _, head := range chainHeads {
		if err := dev.receiveQueue.FreeDescriptorChain(head); err != nil {
			return net.VirtioNetHdr{}, nil,
				fmt.Errorf("free descriptor chain with head index %d: %w", head, err)
		}
	}

	if err := dev.refillReceiveQueue(); err != nil {
		return net.VirtioNetHdr{}, nil, fmt.Errorf("refill receive queue: %w", err)
	}

	return vnethdr, packet, nil
}

func (dev *Device) refillReceiveQueue() error {
	for {
		_, err := dev.receiveQueue.OfferDescriptorChain(nil, 1, false)
		if err != nil {
			if errors.Is(err, vring.ErrNotEnoughFreeDescriptors) {
				return nil
			}
			return fmt.Errorf("offer descriptor chain: %w", err)
		}
	}
}

func createQueue(controlFD int, queueIndex int, queueSize int) (*vring.SplitQueue, error) {
	var (
		queue *vring.SplitQueue
		err   error
	)
	if queue, err = vring.NewSplitQueue(queueSize); err != nil {
		return nil, err
	}
	if err = vhost.RegisterQueue(controlFD, uint32(queueIndex), queue); err != nil {
		return nil, fmt.Errorf("register vring with index %d: %w",
			queueIndex, err)
	}
	return queue, nil
}

func truncateBuffers(buffers [][]byte, length int) (out [][]byte) {
	for _, buffer := range buffers {
		if length < len(buffer) {
			out = append(out, buffer[:length])
			return
		}
		out = append(out, buffer)
		length -= len(buffer)
	}
	if length > 0 {
		panic("length exceeds the combined length of all buffers")
	}
	return
}

func SetQueueBackend(controlFD int, queueIndex uint32, backendFD int) error {
	if err := vhost.IoctlPtr(controlFD,
		vhostNetIoctlSetBackend, unsafe.Pointer(&vhost.VRingFile{
			QueueIndex: queueIndex,
			FD:         int32(backendFD),
		})); err != nil {
		return fmt.Errorf("set vring backend file descriptor: %w", err)
	}
	return nil
}

func (dev *Device) Close() error {

	var errs []error

	dev.initialized = false
	if dev.controlFD >= 0 {
		err := unix.Close(dev.controlFD)
		if err != nil {
			errs = append(errs,
				fmt.Errorf("close control file descriptor: %w", err))
		}
		dev.controlFD = -1
	}

	if dev.receiveQueue != nil {
		if err := dev.receiveQueue.Close(); err == nil {
			dev.receiveQueue = nil
		} else {
			errs = append(errs, fmt.Errorf("close receive queue: %w", err))
		}
	}

	if dev.transmitQueue != nil {
		if err := dev.transmitQueue.Close(); err == nil {
			dev.transmitQueue = nil
		} else {
			errs = append(errs, fmt.Errorf("close transmit queue: %w", err))
		}
	}

	if len(errs) == 0 {
		runtime.SetFinalizer(dev, nil)
	}

	return errors.Join(errs...)
}

func (dev *Device) ensureInitialized() {
	if !dev.initialized {
		panic("device is not initialized")
	}
}
