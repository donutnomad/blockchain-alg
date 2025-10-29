package xecdsa

import (
	"math/big"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/donutnomad/blockchain-alg/xasn1"
)

type ISignature interface {
	R() *big.Int
	S() *big.Int
	// Bytes R || S
	Bytes() []byte
	// DER ASN1
	DER() []byte
	HasV() bool
}

func NewSignature(r, s *big.Int, v *byte) ISignature {
	if v == nil {
		return &RSSignature{r, s}
	} else {
		return &RSVSignature{RSSignature: RSSignature{r: r, s: s}, v: *v}
	}
}

type RSSignature struct {
	r, s *big.Int
}

func (R *RSSignature) R() *big.Int {
	return R.r
}

func (R *RSSignature) S() *big.Int {
	return R.s
}

func (R *RSSignature) Bytes() []byte {
	var bs [64]byte
	R.r.FillBytes(bs[:32])
	R.s.FillBytes(bs[32:])
	return bs[:]
}

func (R *RSSignature) DER() []byte {
	return xasn1.MarshalAsn1SignatureSlice([64]byte(R.Bytes()))
}

func (R *RSSignature) HasV() bool {
	return false
}

type RSVSignature struct {
	RSSignature
	v byte
}

func (R *RSVSignature) V() byte {
	return R.v
}

func (R *RSVSignature) RSV() [65]byte {
	var sig [65]byte
	R.r.FillBytes(sig[0:32])
	R.s.FillBytes(sig[32:64])
	sig[64] = R.v
	return sig
}

func (R *RSVSignature) VRS() [65]byte {
	var sig [65]byte
	sig[0] = R.v
	R.r.FillBytes(sig[1:33])
	R.s.FillBytes(sig[33:65])
	return sig
}

func (R *RSVSignature) HasV() bool {
	return true
}

func scalarToInt(s secp256k1.ModNScalar) *big.Int {
	bs := s.Bytes()
	return new(big.Int).SetBytes(bs[:])
}
