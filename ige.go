package ige

import (
	"crypto/cipher"
	"errors"
)

var (
	ErrInvalidIV = errors.New("initilization vector must be: b.BlockSize()*2")
)

type IGE interface {
	BlockSize() int
	CryptBlocks(dst, src []byte)
}

type ige struct {
	block cipher.Block
	iv    []byte
}

func newIGE(b cipher.Block, iv []byte) *ige {
	i := &ige{b, make([]byte, len(iv))}
	copy(i.iv, iv)
	return i
}

func checkIV(b cipher.Block, iv []byte) error {
	// the initialization vector needs to contain b.Blocksize()*2 bytes because
	// ige uses a two step xor process, and iv[:16] corresponds to the first iv
	// while iv[16:] corresponds to the second iv
	//
	// the original ige paper described the first iv as a random block and the
	// second iv as its encrypted counterpart, however, we're copying the
	// openssl implementation and therefore both ivs are supplied by the user
	if len(iv) != b.BlockSize()*2 {
		return ErrInvalidIV
	}

	return nil
}
