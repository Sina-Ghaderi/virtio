package vring

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"

	"github.com/sina-ghaderi/virtio/eventfd"

	"golang.org/x/sys/unix"
)

type SplitQueue struct {
	size                int
	buf                 []byte
	descriptorTable     *DescriptorTable
	availableRing       *AvailableRing
	usedRing            *UsedRing
	kickEventFD         eventfd.EventFD
	callEventFD         eventfd.EventFD
	usedChains          chan UsedElement
	moreFreeDescriptors chan struct{}
	stop                func() error
	offerMutex          sync.Mutex
}

func NewSplitQueue(queueSize int) (_ *SplitQueue, err error) {
	if err = CheckVRingSize(queueSize); err != nil {
		return nil, err
	}

	sq := SplitQueue{
		size: queueSize,
	}

	defer func() {
		if err != nil {
			_ = sq.Close()
		}
	}()

	descriptorTableStart := 0
	descriptorTableEnd := descriptorTableStart +
		descriptorTableSize(queueSize)
	availableRingStart := align(descriptorTableEnd,
		availableRingAlignment)
	availableRingEnd := availableRingStart +
		availableRingSize(queueSize)
	usedRingStart := align(availableRingEnd,
		usedRingAlignment)
	usedRingEnd := usedRingStart + usedRingSize(queueSize)

	sq.buf, err = unix.Mmap(-1, 0, usedRingEnd,
		unix.PROT_READ|unix.PROT_WRITE,
		unix.MAP_PRIVATE|unix.MAP_ANONYMOUS)
	if err != nil {
		return nil, fmt.Errorf("allocate vring buffer: %w", err)
	}

	sq.descriptorTable = newDescriptorTable(queueSize,
		sq.buf[descriptorTableStart:descriptorTableEnd])
	sq.availableRing = newAvailableRing(queueSize,
		sq.buf[availableRingStart:availableRingEnd])
	sq.usedRing = newUsedRing(queueSize,
		sq.buf[usedRingStart:usedRingEnd])

	sq.kickEventFD, err = eventfd.Create()
	if err != nil {
		return nil, fmt.Errorf("create kick event file descriptor: %w", err)
	}
	sq.callEventFD, err = eventfd.Create()
	if err != nil {
		return nil, fmt.Errorf("create call event file descriptor: %w", err)
	}

	if err = sq.descriptorTable.initializeDescriptors(); err != nil {
		return nil, fmt.Errorf("initialize descriptors: %w", err)
	}

	sq.usedChains = make(chan UsedElement, queueSize)
	sq.moreFreeDescriptors = make(chan struct{})

	sq.stop = sq.startConsumeUsedRing()

	return &sq, nil
}

func (sq *SplitQueue) Size() int {
	sq.ensureInitialized()
	return sq.size
}

func (sq *SplitQueue) DescriptorTable() *DescriptorTable {
	sq.ensureInitialized()
	return sq.descriptorTable
}

func (sq *SplitQueue) AvailableRing() *AvailableRing {
	sq.ensureInitialized()
	return sq.availableRing
}

func (sq *SplitQueue) UsedRing() *UsedRing {
	sq.ensureInitialized()
	return sq.usedRing
}

func (sq *SplitQueue) KickEventFD() int {
	sq.ensureInitialized()
	return sq.kickEventFD.FD()
}

func (sq *SplitQueue) CallEventFD() int {
	sq.ensureInitialized()
	return sq.callEventFD.FD()
}

func (sq *SplitQueue) UsedDescriptorChains() chan UsedElement {
	sq.ensureInitialized()
	return sq.usedChains
}

func (sq *SplitQueue) startConsumeUsedRing() func() error {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error)
	go func() {
		done <- sq.consumeUsedRing(ctx)
	}()
	return func() error {
		cancel()

		if err := sq.callEventFD.Notify(); err != nil {
			return fmt.Errorf("wake up goroutine: %w", err)
		}

		if err := <-done; err != nil {
			return fmt.Errorf("consume used ring: %w", err)
		}
		return nil
	}
}

func (sq *SplitQueue) consumeUsedRing(ctx context.Context) error {
	for ctx.Err() == nil {

		if err := sq.callEventFD.Wait(); err != nil {
			return fmt.Errorf("wait: %w", err)
		}

		for _, usedElement := range sq.usedRing.take() {
			sq.usedChains <- usedElement
		}
	}

	return nil
}

func (sq *SplitQueue) OfferDescriptorChain(outBuffers [][]byte, numInBuffers int, waitFree bool) (uint16, error) {
	sq.ensureInitialized()
	outBuffers = splitBuffers(outBuffers, os.Getpagesize())

	sq.offerMutex.Lock()
	defer sq.offerMutex.Unlock()

	var (
		head uint16
		err  error
	)
	for {
		head, err = sq.descriptorTable.createDescriptorChain(outBuffers, numInBuffers)
		if err == nil {
			break
		}
		if waitFree && errors.Is(err, ErrNotEnoughFreeDescriptors) {

			<-sq.moreFreeDescriptors
			continue
		}
		return 0, fmt.Errorf("create descriptor chain: %w", err)
	}

	sq.availableRing.offer([]uint16{head})

	if err := sq.kickEventFD.Notify(); err != nil {
		return head, fmt.Errorf("notify device: %w", err)
	}

	return head, nil
}

func (sq *SplitQueue) GetDescriptorChain(head uint16) (outBuffers, inBuffers [][]byte, err error) {
	sq.ensureInitialized()
	return sq.descriptorTable.getDescriptorChain(head)
}

func (sq *SplitQueue) FreeDescriptorChain(head uint16) error {
	sq.ensureInitialized()

	if err := sq.descriptorTable.freeDescriptorChain(head); err != nil {
		return fmt.Errorf("free: %w", err)
	}

	select {
	case sq.moreFreeDescriptors <- struct{}{}:
	default:
	}

	return nil
}

func (sq *SplitQueue) Close() error {
	var errs []error

	if sq.stop != nil {

		if err := sq.stop(); err != nil {
			errs = append(errs, fmt.Errorf("stop consume used ring: %w", err))
		}

		close(sq.usedChains)

		sq.stop = nil
	}

	if err := sq.kickEventFD.Close(); err != nil {
		errs = append(errs, fmt.Errorf("close kick event file descriptor: %w", err))
	}
	if err := sq.callEventFD.Close(); err != nil {
		errs = append(errs, fmt.Errorf("close call event file descriptor: %w", err))
	}

	if err := sq.descriptorTable.releaseBuffers(); err != nil {
		errs = append(errs, fmt.Errorf("release descriptor buffers: %w", err))
	}

	if sq.buf != nil {
		if err := unix.Munmap(sq.buf); err == nil {
			sq.buf = nil
		} else {
			errs = append(errs, fmt.Errorf("unmap vring buffer: %w", err))
		}
	}

	return errors.Join(errs...)
}

func (sq *SplitQueue) ensureInitialized() {
	if sq.buf == nil {
		panic("used ring is not initialized")
	}
}

func align(index, alignment int) int {
	remainder := index % alignment
	if remainder == 0 {
		return index
	}
	return index + alignment - remainder
}

func splitBuffers(buffers [][]byte, sizeLimit int) [][]byte {
	result := make([][]byte, 0, len(buffers))
	for _, buffer := range buffers {
		for added := 0; added < len(buffer); added += sizeLimit {
			if len(buffer)-added <= sizeLimit {
				result = append(result, buffer[added:])
				break
			}
			result = append(result, buffer[added:added+sizeLimit])
		}
	}

	return result
}
