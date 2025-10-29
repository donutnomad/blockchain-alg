package xasn1

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/samber/lo"
)

func TestMarshalSigRS(t *testing.T) {
	var r = mustRand(31)
	var s = mustRand(31)
	var asn1Sig = MarshalAsn1SignatureRS(r, s)
	var rr, ss, err = ParseSignatureRS(asn1Sig)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(padSliceLeft(r, 32), rr) || !bytes.Equal(padSliceLeft(s, 32), ss) {
		t.Fatalf("marshal failed")
	}
}

func mustRand(size int) []byte {
	var out = make([]byte, size)
	lo.Must1(rand.Reader.Read(out))
	return out
}
