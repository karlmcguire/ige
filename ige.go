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

type igeEncrypter ige

func (i *igeEncrypter) BlockSize() int {
	return i.block.BlockSize()
}

func (i *igeEncrypter) CryptBlocks(dst, src []byte) {
	if len(src)%i.block.BlockSize() != 0 {
		panic("src not full blocks")
	}
	if len(dst) < len(src) {
		panic("len(dst) < len(src")
	}

	b := i.block.BlockSize()
	c := i.iv[:b]
	m := i.iv[b:]

	for o := 0; o < len(src); o += b {
		xor(dst[o:o+b], src[o:o+b], c)
		i.block.Encrypt(dst[o:o+b], dst[o:o+b])
		xor(dst[o:o+b], dst[o:o+b], m)

		c = dst[o : o+b]
		m = src[o : o+b]
	}
}

type igeDecrypter ige

func (i *igeDecrypter) BlockSize() int {
	return i.block.BlockSize()
}

func (i *igeDecrypter) CryptBlocks(dst, src []byte) {
	if len(src)%i.block.BlockSize() != 0 {
		panic("src not full blocks")
	}
	if len(dst) < len(src) {
		panic("len(dst) < len(src)")
	}

	b := i.block.BlockSize()
	c := i.iv[:b]
	m := i.iv[b:]
	t := make([]byte, b)

	for o := 0; o < len(src); o += b {
		t = src[o : o+b]

		xor(dst[o:o+b], src[o:o+b], m)
		i.block.Decrypt(dst[o:o+b], dst[o:o+b])
		xor(dst[o:o+b], dst[o:o+b], c)

		m = dst[o : o+b]
		c = t
	}
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

func NewIGEEncrypter(b cipher.Block, iv []byte) IGE {
	if err := checkIV(b, iv); err != nil {
		panic(err.Error())
	}

	return (*igeEncrypter)(newIGE(b, iv))
}

func NewIGEDecrypter(b cipher.Block, iv []byte) IGE {
	if err := checkIV(b, iv); err != nil {
		panic(err.Error())
	}

	return (*igeDecrypter)(newIGE(b, iv))
}
