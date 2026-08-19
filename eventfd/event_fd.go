package eventfd

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/unix"
)

type EventFD struct {
	fd int
}

// Create initializes a new eventfd.
func Create() (EventFD, error) {
	fd, _, err := unix.RawSyscall(
		unix.SYS_EVENTFD2, 0, unix.O_CLOEXEC, 0)

	efd := EventFD{}

	if err != 0 {
		return efd, fmt.Errorf("create eventfd: %v", err)
	}
	efd.fd = int(fd)
	return efd, nil
}

// Notify alerts other users of the eventfd by writing a value of 1.
func (e EventFD) Notify() error {
	val := uint64(1)
	buf := (*[8]byte)(unsafe.Pointer(&val))[:]

	for {
		n, err := unix.Write(e.fd, buf)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return fmt.Errorf("write to eventfd: %v", err)
		}
		if n != 8 {
			return fmt.Errorf("short write to eventfd: got %d bytes, wanted 8", n)
		}
		return nil
	}
}

// Wait blocks until the eventfd is non-zero (i.e. someone calls Notify).
func (e EventFD) Wait() error {
	var buf [8]byte

	for {
		n, err := unix.Read(e.fd, buf[:])
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return fmt.Errorf("read from eventfd: %v", err)
		}
		if n != 8 {
			return fmt.Errorf("short read from eventfd: got %d bytes, wanted 8", n)
		}
		return nil
	}
}

// Close closes the eventfd.
func (e EventFD) Close() error {
	return unix.Close(e.fd)
}

// Fd returns the underlying file descriptor if you ever need to pass it to poll/epoll.
func (e EventFD) FD() int {
	return e.fd
}
