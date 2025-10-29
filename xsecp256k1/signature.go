package xsecp256k1

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	secp_ecdsa "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
)

type Signature struct {
	r, s *big.Int
}

func NewSignature(r *big.Int, s *big.Int) Signature {
	return Signature{r: r, s: s}
}
func NewSignatureWithBs(bs [64]byte) Signature {
	return Signature{r: new(big.Int).SetBytes(bs[0:32]), s: new(big.Int).SetBytes(bs[32:64])}
}
func (s *Signature) Signature() Signature {
	return *s
}
func (s *Signature) Bytes() []byte {
	out := s.BytesRS()
	return out[:]
}
func (s *Signature) BytesRS() (sig [64]byte) {
	s.r.FillBytes(sig[0:32])
	s.s.FillBytes(sig[32:64])
	return sig
}
func (s *Signature) R() *big.Int {
	return s.r
}
func (s *Signature) S() *big.Int {
	return s.s
}

type SignatureCompat struct {
	r, s *big.Int
	v    byte
}

func NewSignatureCompat(r *big.Int, s *big.Int, v byte) SignatureCompat {
	return SignatureCompat{r: r, s: s, v: v}
}
func NewSignatureCompatWithBs(bs [65]byte) SignatureCompat {
	return NewSignatureCompat(new(big.Int).SetBytes(bs[:32]), new(big.Int).SetBytes(bs[32:64]), bs[64])
}
func NewSignatureCompatWith(sig Signature, v byte) SignatureCompat {
	return SignatureCompat{r: new(big.Int).Set(sig.r), s: new(big.Int).Set(sig.s), v: v}
}

func (s *SignatureCompat) Signature() Signature {
	return Signature{s.r, s.s}
}

func (s *SignatureCompat) R() *big.Int {
	return s.r
}
func (s *SignatureCompat) S() *big.Int {
	return s.s
}
func (s *SignatureCompat) V() byte {
	return s.v
}
func (s *SignatureCompat) Bytes() []byte {
	out := s.BytesVRS()
	return out[:]
}
func (s *SignatureCompat) BytesVRS() [65]byte {
	var sig [65]byte
	sig[0] = s.v
	s.r.FillBytes(sig[1:33])
	s.s.FillBytes(sig[33:65])
	return sig
}
func (s *SignatureCompat) BytesRSV() [65]byte {
	var sig [65]byte
	s.r.FillBytes(sig[0:32])
	s.s.FillBytes(sig[32:64])
	sig[64] = s.v
	return sig
}

// VerifyEthereumSignature checks that the given public key created signature over hash.
// The public key should be in compressed (33 bytes) or uncompressed (65 bytes) format.
func VerifyEthereumSignature(pubKey []byte, rBig, sBig *big.Int, hash []byte) bool {
	key, err := secp256k1.ParsePubKey(pubKey)
	if err != nil {
		return false
	}
	var r, s secp256k1.ModNScalar
	if overflow := r.SetByteSlice(rBig.Bytes()); overflow {
		return false
	}
	if overflow := s.SetByteSlice(sBig.Bytes()); overflow {
		return false
	}
	sig := secp_ecdsa.NewSignature(&r, &s)
	// Reject malleable signatures. libsecp256k1 does this check but btcec doesn't.
	if s.IsOverHalfOrder() {
		return false
	}

	return sig.Verify(hash, key)
}

// ParseSignature parses a signature in BER format for the curve type `curve'
// into a Signature type, perfoming some basic sanity checks.  If parsing
// according to the more strict DER format is needed, use ParseDERSignature.
func ParseSignature(sigStr []byte) (*Signature, error) {
	sig, err := parseSig(sigStr, false)
	if err != nil {
		return nil, err
	}
	return &Signature{
		r: scalarToInt(sig.R()),
		s: scalarToInt(sig.S()),
	}, nil
}

// ParseDERSignature parses a signature in DER format for the curve type
// `curve` into a Signature type.  If parsing according to the less strict
// BER format is needed, use ParseSignature.
func ParseDERSignature(sigStr []byte) (*Signature, error) {
	sig, err := parseSig(sigStr, true)
	if err != nil {
		return nil, err
	}
	return &Signature{
		r: scalarToInt(sig.R()),
		s: scalarToInt(sig.S()),
	}, nil
}

func scalarToInt(s secp256k1.ModNScalar) *big.Int {
	bs := s.Bytes()
	return new(big.Int).SetBytes(bs[:])
}

/////// from github.com/btcsuite/btcd/btcec/v2@v2.3.2/ecdsa/signature.go

// MinSigLen is the minimum length of a DER encoded signature and is when both R
// and S are 1 byte each.
// 0x30 + <1-byte> + 0x02 + 0x01 + <byte> + 0x2 + 0x01 + <byte>
const MinSigLen = 8

// Errors returned by canonicalPadding.
var (
	errNegativeValue          = errors.New("value may be interpreted as negative")
	errExcessivelyPaddedValue = errors.New("value is excessively padded")
)

// canonicalPadding checks whether a big-endian encoded integer could
// possibly be misinterpreted as a negative number (even though OpenSSL
// treats all numbers as unsigned), or if there is any unnecessary
// leading zero padding.
func canonicalPadding(b []byte) error {
	switch {
	case b[0]&0x80 == 0x80:
		return errNegativeValue
	case len(b) > 1 && b[0] == 0x00 && b[1]&0x80 != 0x80:
		return errExcessivelyPaddedValue
	default:
		return nil
	}
}

func parseSig(sigStr []byte, der bool) (*secp_ecdsa.Signature, error) {
	// Originally this code used encoding/asn1 in order to parse the
	// signature, but a number of problems were found with this approach.
	// Despite the fact that signatures are stored as DER, the difference
	// between go's idea of a bignum (and that they have sign) doesn't agree
	// with the openssl one (where they do not). The above is true as of
	// Go 1.1. In the end it was simpler to rewrite the code to explicitly
	// understand the format which is this:
	// 0x30 <length of whole message> <0x02> <length of R> <R> 0x2
	// <length of S> <S>.

	if len(sigStr) < MinSigLen {
		return nil, errors.New("malformed signature: too short")
	}
	// 0x30
	index := 0
	if sigStr[index] != 0x30 {
		return nil, errors.New("malformed signature: no header magic")
	}
	index++
	// length of remaining message
	siglen := sigStr[index]
	index++

	// siglen should be less than the entire message and greater than
	// the minimal message size.
	if int(siglen+2) > len(sigStr) || int(siglen+2) < MinSigLen {
		return nil, errors.New("malformed signature: bad length")
	}
	// trim the slice we're working on so we only look at what matters.
	sigStr = sigStr[:siglen+2]

	// 0x02
	if sigStr[index] != 0x02 {
		return nil,
			errors.New("malformed signature: no 1st int marker")
	}
	index++

	// Length of signature R.
	rLen := int(sigStr[index])
	// must be positive, must be able to fit in another 0x2, <len> <s>
	// hence the -3. We assume that the length must be at least one byte.
	index++
	if rLen <= 0 || rLen > len(sigStr)-index-3 {
		return nil, errors.New("malformed signature: bogus R length")
	}

	// Then R itself.
	rBytes := sigStr[index : index+rLen]
	if der {
		switch err := canonicalPadding(rBytes); err {
		case errNegativeValue:
			return nil, errors.New("signature R is negative")
		case errExcessivelyPaddedValue:
			return nil, errors.New("signature R is excessively padded")
		}
	}

	// Strip leading zeroes from R.
	for len(rBytes) > 0 && rBytes[0] == 0x00 {
		rBytes = rBytes[1:]
	}

	// R must be in the range [1, N-1].  Notice the check for the maximum number
	// of bytes is required because SetByteSlice truncates as noted in its
	// comment so it could otherwise fail to detect the overflow.
	var r secp256k1.ModNScalar
	if len(rBytes) > 32 {
		str := "invalid signature: R is larger than 256 bits"
		return nil, errors.New(str)
	}
	if overflow := r.SetByteSlice(rBytes); overflow {
		str := "invalid signature: R >= group order"
		return nil, errors.New(str)
	}
	if r.IsZero() {
		str := "invalid signature: R is 0"
		return nil, errors.New(str)
	}
	index += rLen
	// 0x02. length already checked in previous if.
	if sigStr[index] != 0x02 {
		return nil, errors.New("malformed signature: no 2nd int marker")
	}
	index++

	// Length of signature S.
	sLen := int(sigStr[index])
	index++
	// S should be the rest of the string.
	if sLen <= 0 || sLen > len(sigStr)-index {
		return nil, errors.New("malformed signature: bogus S length")
	}

	// Then S itself.
	sBytes := sigStr[index : index+sLen]
	if der {
		switch err := canonicalPadding(sBytes); err {
		case errNegativeValue:
			return nil, errors.New("signature S is negative")
		case errExcessivelyPaddedValue:
			return nil, errors.New("signature S is excessively padded")
		}
	}

	// Strip leading zeroes from S.
	for len(sBytes) > 0 && sBytes[0] == 0x00 {
		sBytes = sBytes[1:]
	}

	// S must be in the range [1, N-1].  Notice the check for the maximum number
	// of bytes is required because SetByteSlice truncates as noted in its
	// comment so it could otherwise fail to detect the overflow.
	var s secp256k1.ModNScalar
	if len(sBytes) > 32 {
		str := "invalid signature: S is larger than 256 bits"
		return nil, errors.New(str)
	}
	if overflow := s.SetByteSlice(sBytes); overflow {
		str := "invalid signature: S >= group order"
		return nil, errors.New(str)
	}
	if s.IsZero() {
		str := "invalid signature: S is 0"
		return nil, errors.New(str)
	}
	index += sLen

	// sanity check length parsing
	if index != len(sigStr) {
		return nil, fmt.Errorf("malformed signature: bad final length %v != %v",
			index, len(sigStr))
	}

	return secp_ecdsa.NewSignature(&r, &s), nil
}
