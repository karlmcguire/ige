package ige

import (
	"bytes"
	"testing"
)

func TestXorSafe(t *testing.T) {
	var (
		d = make([]byte, 4)
		a = make([]byte, 4)
		b = []byte{0xff, 0xff, 0xff}
	)

	if l := safe(d, a, b); l != 3 {
		t.Fatal("safe returned wrong length")
	}

	if !bytes.Equal(d[:3], b) {
		t.Fatal("safe didn't xor properly")
	}
}

func TestXorFast(t *testing.T) {
	var (
		d = make([]byte, 8)
		a = make([]byte, 8)
		b = []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	)

	if l := fast(d, a, b); l != 7 {
		t.Fatal("fast returned wrong length")
	}

	if !bytes.Equal(d[:7], b) {
		t.Fatal("fast didn't xor properly")
	}

	if l := fast(d, a, nil); l != 0 {
		t.Fatal("fast returned wrong length")
	}
}
