package xed25519

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

func TestSign(t *testing.T) {
	_, pri, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	message := []byte("data to be signed")
	p1 := ed25519.Sign(pri, message)
	p2 := Sign(pri, message)

	if !bytes.Equal(p1, p2) {
		panic("invalid signature")
	}
}
