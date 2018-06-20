package ige

import (
	"crypto/cipher"
)

type IGE interface {
	Blocksize() int
	CryptBlocks(dst, src []byte)
}

func NewIGE(b cipher.Block, iv []byte) IGE { return &ige{b, iv} }

type ige struct {
	block cipher.Block
	iv    []byte
}

func (i *ige) Blocksize() int { return 0 }

func (i *ige) CryptBlocks(dst, src []byte) {
	// the length of src must be a multiple of the block size
}
