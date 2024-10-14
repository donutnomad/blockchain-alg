package hashs

import (
	"crypto/sha512"
	"iter"
)

type Bytes64 [64]byte

func (b Bytes64) Bytes() []byte {
	return b[:]
}

func SHA512[S ~[]byte](messages ...S) (out Bytes64) {
	h := sha512.New()
	for _, message := range messages {
		h.Write(message)
	}
	h.Sum(out[:0])
	return
}

func SHA512Iter[S ~[]byte](it iter.Seq[S]) (out Bytes64) {
	h := sha512.New()
	for message := range it {
		h.Write(message)
	}
	h.Sum(out[:0])
	return
}
