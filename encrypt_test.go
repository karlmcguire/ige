package ige

import (
	"bytes"
	"crypto/aes"
	"testing"
)

func TestNewIGEEncrypter(t *testing.T) {
	c, err := aes.NewCipher(make([]byte, 16))
	if err != nil {
		t.Fatal(err)
	}

	defer func() {
		if r := recover(); r == nil {
			t.Fatal("NewIGEEncrypter didn't panic with bad iv")
		}
	}()

	_ = NewIGEEncrypter(c, []byte{})
}

func TestEncrypterBlockSize(t *testing.T) {
	c, err := aes.NewCipher(make([]byte, 16))
	if err != nil {
		t.Fatal(err)
	}

	i := NewIGEEncrypter(c, make([]byte, 32))

	if i.BlockSize() != 16 {
		t.Fatalf("encrypter.BlockSize() != 16, got %d instead\n", i.BlockSize())
	}
}

func TestEncrypterCryptBlocks(t *testing.T) {
	for a, v := range TestVectors {
		out := make([]byte, len(v.Ciphertext))

		c, err := aes.NewCipher(v.Key)
		if err != nil {
			t.Fatal(err)
		}

		i := NewIGEEncrypter(c, v.IV)
		i.CryptBlocks(out, v.Plaintext)

		if !bytes.Equal(out, v.Ciphertext) {
			t.Fatalf("test vector %d has wrong ciphertext\n", a+1)
		}
	}
}

func TestEncryptCryptBlocksPanicSrc(t *testing.T) {
	c, err := aes.NewCipher(make([]byte, 16))
	if err != nil {
		t.Fatal(err)
	}

	defer func() {
		if r := recover(); r == nil {
			t.Fatal("encrypt.CryptBlocks() not panicking with bad src")
		}
	}()

	i := NewIGEEncrypter(c, make([]byte, 32))
	i.CryptBlocks(make([]byte, 16), make([]byte, 1))
}

func TestEncryptCryptBlocksPanicDst(t *testing.T) {
	c, err := aes.NewCipher(make([]byte, 16))
	if err != nil {
		t.Fatal(err)
	}

	defer func() {
		if r := recover(); r == nil {
			t.Fatal("encrypt.CryptBlocks() not panicking with bad dst")
		}
	}()

	i := NewIGEEncrypter(c, make([]byte, 32))
	i.CryptBlocks(make([]byte, 1), make([]byte, 16))
}
