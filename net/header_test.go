package net

import (
	"encoding/binary"
	"math/rand"
	"testing"
)

func TestFlagAndGsoTypeConstants(t *testing.T) {
	cases := []struct {
		name string
		got  int
		want int
	}{
		{"VIRTIO_NET_HDR_F_NEEDS_CSUM", VirtioNetHdrNeedsCSUM, 0x1},
		{"VIRTIO_NET_HDR_F_DATA_VALID", VirtioNetHdrDataValid, 0x2},
		{"VIRTIO_NET_HDR_F_RSC_INFO", VirtioNetHdrRSCInfo, 0x4},
		{"VIRTIO_NET_HDR_GSO_NONE", VirtioNetHdrGsoNone, 0x0},
		{"VIRTIO_NET_HDR_GSO_TCPV4", VirtioNetHdrGsoTCPV4, 0x1},
		{"VIRTIO_NET_HDR_GSO_UDP", VirtioNetHdrGsoUDP, 0x3},
		{"VIRTIO_NET_HDR_GSO_TCPV6", VirtioNetHdrGsoTCPV6, 0x4},
		{"VIRTIO_NET_HDR_GSO_UDP_L4", VirtioNetHdrGsoUDPL4, 0x5},
		{"VIRTIO_NET_HDR_GSO_ECN", VirtioNetHdrGsoECN, 0x80},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("%s = %#x, want %#x", c.name, c.got, c.want)
		}
	}
}

func rawVnetHdrBytes(flags, gsoType uint8, hdrLen, gsoSize, csumStart, csumOffset uint16) []byte {
	b := make([]byte, VirtioNetHdrLen)
	b[0] = flags
	b[1] = gsoType
	binary.NativeEndian.PutUint16(b[2:4], hdrLen)
	binary.NativeEndian.PutUint16(b[4:6], gsoSize)
	binary.NativeEndian.PutUint16(b[6:8], csumStart)
	binary.NativeEndian.PutUint16(b[8:10], csumOffset)
	return b
}

func TestDecode_FieldByteOffsets(t *testing.T) {
	raw := rawVnetHdrBytes(0x1, 0x4, 0x1234, 0x5678, 0x9abc, 0xdef0)

	var v VirtioNetHdr
	if err := v.Decode(raw); err != nil {
		t.Fatalf("Decode: unexpected error: %v", err)
	}

	switch {
	case v.Flags != 0x1:
		t.Errorf("Flags = %#x, want 0x1", v.Flags)
	case v.GsoType != 0x4:
		t.Errorf("GsoType = %#x, want 0x4", v.GsoType)
	case v.HdrLen != 0x1234:
		t.Errorf("HdrLen = %#x, want 0x1234", v.HdrLen)
	case v.GsoSize != 0x5678:
		t.Errorf("GsoSize = %#x, want 0x5678", v.GsoSize)
	case v.CsumStart != 0x9abc:
		t.Errorf("CsumStart = %#x, want 0x9abc", v.CsumStart)
	case v.CsumOffset != 0xdef0:
		t.Errorf("CsumOffset = %#x, want 0xdef0", v.CsumOffset)
	}
}

func TestEncode_FieldByteOffsets(t *testing.T) {
	v := VirtioNetHdr{
		Flags:      0x2,
		GsoType:    0x5,
		HdrLen:     0x1111,
		GsoSize:    0x2222,
		CsumStart:  0x3333,
		CsumOffset: 0x4444,
	}

	got := make([]byte, VirtioNetHdrLen)
	if err := v.Encode(got); err != nil {
		t.Fatalf("Encode: unexpected error: %v", err)
	}

	want := rawVnetHdrBytes(0x2, 0x5, 0x1111, 0x2222, 0x3333, 0x4444)
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("byte %d: got %#02x, want %#02x (got=%x want=%x)", i, got[i], want[i], got, want)
		}
	}
}

func TestDecodeEncode_Symmetric(t *testing.T) {
	rng := rand.New(rand.NewSource(42))

	extremes := []uint16{0, 1, 0xff, 0x100, 0x7fff, 0x8000, 0xfffe, 0xffff}

	for i := 0; i < 500; i++ {
		var v VirtioNetHdr
		v.Flags = uint8(rng.Intn(256))
		v.GsoType = uint8(rng.Intn(256))
		if i < len(extremes)*4 {

			v.HdrLen = extremes[i%len(extremes)]
			v.GsoSize = extremes[(i/2)%len(extremes)]
			v.CsumStart = extremes[(i/3)%len(extremes)]
			v.CsumOffset = extremes[(i/5)%len(extremes)]
		} else {
			v.HdrLen = uint16(rng.Intn(65536))
			v.GsoSize = uint16(rng.Intn(65536))
			v.CsumStart = uint16(rng.Intn(65536))
			v.CsumOffset = uint16(rng.Intn(65536))
		}

		buf := make([]byte, VirtioNetHdrLen)
		if err := v.Encode(buf); err != nil {
			t.Fatalf("iter %d: Encode: %v", i, err)
		}

		var got VirtioNetHdr
		if err := got.Decode(buf); err != nil {
			t.Fatalf("iter %d: Decode: %v", i, err)
		}

		if got != v {
			t.Fatalf("iter %d: round trip mismatch: put %+v, got %+v", i, v, got)
		}
	}
}

func TestDecode_ShortBuffer(t *testing.T) {
	for n := 0; n < VirtioNetHdrLen; n++ {
		n := n
		t.Run("", func(t *testing.T) {
			b := make([]byte, n)
			sentinel := VirtioNetHdr{Flags: 0xaa, GsoType: 0xbb, HdrLen: 0xcccc,
				GsoSize: 0xdddd, CsumStart: 0xeeee, CsumOffset: 0xffff}
			v := sentinel

			err := v.Decode(b)
			if err == nil || err.Error() != "short virtio nethdr buffer length" {
				t.Fatalf("len(b)=%d: err = %v, want "+
					"'short virtio nethdr buffer length'", n, err)
			}
			if v != sentinel {
				t.Fatalf(
					"len(b)=%d: struct mutated on short-buffer error: "+
						" got %+v, want untouched %+v", n, v, sentinel)
			}
		})
	}

	b := make([]byte, VirtioNetHdrLen)
	var v VirtioNetHdr
	if err := v.Decode(b); err != nil {
		t.Fatalf("len(b)=VirtioNetHdrLen: unexpected error: %v", err)
	}
}

func TestEncode_ShortBuffer(t *testing.T) {
	v := VirtioNetHdr{Flags: 1, GsoType: 1, HdrLen: 40, GsoSize: 1440, CsumStart: 20, CsumOffset: 16}

	for n := 0; n < VirtioNetHdrLen; n++ {
		n := n
		t.Run("", func(t *testing.T) {
			b := make([]byte, n)
			for i := range b {
				b[i] = 0x5a
			}
			err := v.Encode(b)
			if err == nil || err.Error() != "short virtio nethdr buffer length" {
				t.Fatalf("len(b)=%d: err = %v, want short virtio nethdr buffer length", n, err)
			}
			for i, x := range b {
				if x != 0x5a {
					t.Fatalf("len(b)=%d: byte %d mutated on "+
						"short-buffer error: got %#x, want untouched 0x5a", n, i, x)
				}
			}
		})
	}
}

func TestDecode_IgnoresTrailingBytes(t *testing.T) {
	raw := rawVnetHdrBytes(1, 1, 40, 1440, 20, 16)
	trailer := []byte{0xde, 0xad, 0xbe, 0xef, 0x00, 0x11, 0x22}
	full := append(append([]byte{}, raw...), trailer...)

	var v VirtioNetHdr
	if err := v.Decode(full); err != nil {
		t.Fatalf("Decode: unexpected error: %v", err)
	}
	want := VirtioNetHdr{Flags: 1, GsoType: 1, HdrLen: 40, GsoSize: 1440, CsumStart: 20, CsumOffset: 16}
	if v != want {
		t.Fatalf("got %+v, want %+v", v, want)
	}
}

func TestEncode_IgnoresTrailingCapacity(t *testing.T) {
	v := VirtioNetHdr{Flags: 1, GsoType: 4, HdrLen: 60, GsoSize: 1220, CsumStart: 40, CsumOffset: 16}

	buf := make([]byte, VirtioNetHdrLen+8)
	for i := VirtioNetHdrLen; i < len(buf); i++ {
		buf[i] = 0x77
	}
	if err := v.Encode(buf); err != nil {
		t.Fatalf("Encode: unexpected error: %v", err)
	}
	for i := VirtioNetHdrLen; i < len(buf); i++ {
		if buf[i] != 0x77 {
			t.Fatalf("byte %d beyond VirtioNetHdrLen was touched: "+
				"got %#x, want untouched 0x77", i, buf[i])
		}
	}

	var got VirtioNetHdr
	if err := got.Decode(buf); err != nil {
		t.Fatalf("Decode: unexpected error: %v", err)
	}
	if got != v {
		t.Fatalf("got %+v, want %+v", got, v)
	}
}

func TestZeroValueRoundTrips(t *testing.T) {
	buf := make([]byte, VirtioNetHdrLen)
	var v VirtioNetHdr
	if err := v.Decode(buf); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if v != (VirtioNetHdr{}) {
		t.Fatalf("got %+v, want zero value", v)
	}

	out := make([]byte, VirtioNetHdrLen)
	if err := v.Encode(out); err != nil {
		t.Fatalf("Encode: %v", err)
	}
	for i, b := range out {
		if b != 0 {
			t.Fatalf("byte %d = %#x, want 0", i, b)
		}
	}
}
