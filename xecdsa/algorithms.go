package xecdsa

import (
	"crypto/elliptic"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

type Algorithm int

const (
	Unknown Algorithm = 0
	// P224 NIST P-224 (FIPS 186-3, section D.2.2),
	// also known as secp224r1
	// BitLen: 224 Bytes: 28
	// N: 26959946667150639794667015087019625940457807714424391721682722368061
	P224 Algorithm = 1
	// P256 NIST P-256 (FIPS 186-3, section D.2.3),
	// also known as secp256r1 or prime256v1
	// BitLen: 253-256 Bytes: 32
	// N: 115792089210356248762697446949407573529996955224135760342422259061068512044369
	P256 Algorithm = 2
	// P384 NIST P-384 (FIPS 186-3, section D.2.4),
	// also known as secp384r1
	// BitLen: 384 Bytes: 48
	// N: 39402006196394479212279040100143613805079739270465446667946905279627659399113263569398956308152294913554433653942643
	P384 Algorithm = 3
	// P521 NIST P-521 (FIPS 186-3, section D.2.5),
	// also known as secp521r1.
	// BitLen: 521 Bytes: 65-66
	// N: 6864797660130609714981900799081393217269435300143305409394463459185543183397655394245057746333217197532963996371363321113864768612440380340372808892707005449
	P521 Algorithm = 4
	// Secp256k1
	// BitLen: 256 Bytes: 32
	// N: 115792089237316195423570985008687907852837564279074904382605163141518161494337
	Secp256k1 Algorithm = 5
)

func (a Algorithm) FromCurve(curve elliptic.Curve) Algorithm {
	switch curve.Params() {
	case elliptic.P224().Params():
		return P224
	case elliptic.P256().Params():
		return P256
	case elliptic.P384().Params():
		return P384
	case elliptic.P521().Params():
		return P521
	case secp256k1.S256().Params():
		return Secp256k1
	default:
		return Unknown
	}
}

func (a Algorithm) Curve() elliptic.Curve {
	switch a {
	case P224:
		return elliptic.P224()
	case P256:
		return elliptic.P256()
	case P384:
		return elliptic.P384()
	case P521:
		return elliptic.P521()
	case Secp256k1:
		return secp256k1.S256()
	default:
		panic("unreachable")
	}
}
