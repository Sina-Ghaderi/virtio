//go:build linux || android

package offload

import (
	"io"
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

var _zero uintptr

func writeVector(file *os.File, vhdr, hdr []byte, vlen int, iovs [][]byte) (err error) {

	iovecs := make([]unix.Iovec, 0, batchProcess)
	iovecs = appendHdr(iovecs, vhdr, hdr)
	iovecs = appendBytes(iovecs, iovs)

	var n int
	n, err = writeVectorSyscall(file.Fd(), iovecs)
	if n < 0 {
		n = 0
	}

	if n == 0 {
		err = io.ErrUnexpectedEOF
	} else if n != len(vhdr)+len(hdr)+vlen {
		err = io.ErrShortWrite
	}

	if err != nil {
		err = wrapErr("write", file.Name(), err)
	}

	return err
}

func wrapErr(op string, path string, err error) error {
	if err == nil || err == io.EOF {
		return err
	}
	if err == syscall.EBADF {
		err = os.ErrClosed
	}

	return &os.PathError{Op: op, Err: err, Path: path}
}

func appendHdr(vecs []unix.Iovec, vhdr, hdr []byte) []unix.Iovec {
	var v unix.Iovec
	v.SetLen(len(vhdr))
	if len(vhdr) > 0 {
		v.Base = &vhdr[0]
	} else {
		v.Base = (*byte)(unsafe.Pointer(&_zero))
	}

	var x unix.Iovec
	x.SetLen(len(hdr))
	if len(hdr) > 0 {
		x.Base = &hdr[0]
	} else {
		x.Base = (*byte)(unsafe.Pointer(&_zero))
	}

	return append(vecs, v, x)

}

func appendBytes(vecs []unix.Iovec, bs [][]byte) []unix.Iovec {
	for _, b := range bs {
		var v unix.Iovec
		v.SetLen(len(b))
		if len(b) > 0 {
			v.Base = &b[0]
		} else {
			v.Base = (*byte)(unsafe.Pointer(&_zero))
		}
		vecs = append(vecs, v)
	}
	return vecs
}

func writeVectorSyscall(fd uintptr, iovs []unix.Iovec) (n int, err error) {
	var _p0 unsafe.Pointer
	if len(iovs) > 0 {
		_p0 = unsafe.Pointer(&iovs[0])
	} else {
		_p0 = unsafe.Pointer(&_zero)
	}
	r0, _, e1 := syscall.Syscall(unix.SYS_WRITEV,
		fd,
		uintptr(_p0),
		uintptr(len(iovs)),
	)

	n = int(r0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func errnoErr(e syscall.Errno) error {
	switch e {
	case 0:
		return nil
	case syscall.EAGAIN:
		return errEAGAIN
	case syscall.EINVAL:
		return errEINVAL
	case syscall.ENOENT:
		return errENOENT
	}
	return e
}

var (
	errEAGAIN error = syscall.EAGAIN
	errEINVAL error = syscall.EINVAL
	errENOENT error = syscall.ENOENT
)
