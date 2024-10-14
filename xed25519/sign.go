package xed25519

import (
	"crypto/ed25519"
	"crypto/sha512"
	"filippo.io/edwards25519"
)

// from crypto/ed25519/ed25519.go

// Domain separation prefixes used to disambiguate Ed25519/Ed25519ph/Ed25519ctx.
// See RFC 8032, Section 2 and Section 5.1.
const (
	// domPrefixPure is empty for pure Ed25519.
	domPrefixPure = ""
)

// Sign signs the message with privateKey and returns a signature. It will
// panic if len(privateKey) is not [PrivateKeySize].
func Sign(privateKey ed25519.PrivateKey, message []byte) []byte {
	return ed25519.Sign(privateKey, message)
}

func SignFromScalar(privateKey, publicKey, r [32]byte, message []byte, domPrefix, context string) (signature [64]byte) {
	s := must(edwards25519.NewScalar().SetBytesWithClamping(privateKey[:]))
	rs, err := edwards25519.NewScalar().SetCanonicalBytes(r[:])
	if err != nil {
		panic("ed25519: internal error: setting scalar failed")
	}
	R := new(edwards25519.Point).ScalarBaseMult(rs)

	kh := sha512.New()
	if domPrefix != domPrefixPure {
		kh.Write([]byte(domPrefix))
		kh.Write([]byte{byte(len(context))})
		kh.Write([]byte(context))
	}
	kh.Write(R.Bytes())
	kh.Write(publicKey[:])
	kh.Write(message)
	hramDigest := make([]byte, 0, sha512.Size)
	hramDigest = kh.Sum(hramDigest)
	k := must(edwards25519.NewScalar().SetUniformBytes(hramDigest))
	S := edwards25519.NewScalar().MultiplyAdd(k, s, rs)

	copy(signature[:32], R.Bytes())
	copy(signature[32:], S.Bytes())
	return signature
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}
