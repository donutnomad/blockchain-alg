package xecdsa

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"math/big"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

func SerializeCompressed(publicKey *ecdsa.PublicKey) []byte {
	if publicKey.Curve.Params().N == secp256k1.S256().N {
		x := new(secp256k1.FieldVal)
		y := new(secp256k1.FieldVal)
		x.SetByteSlice(publicKey.X.Bytes())
		y.SetByteSlice(publicKey.Y.Bytes())
		return secp256k1.NewPublicKey(x, y).SerializeCompressed()
	} else {
		return elliptic.MarshalCompressed(publicKey.Curve, publicKey.X, publicKey.Y)
	}
}

func SerializeUncompressed(publicKey *ecdsa.PublicKey) []byte {
	if publicKey.Curve.Params().N == secp256k1.S256().N {
		x := new(secp256k1.FieldVal)
		y := new(secp256k1.FieldVal)
		x.SetByteSlice(publicKey.X.Bytes())
		y.SetByteSlice(publicKey.Y.Bytes())
		return secp256k1.NewPublicKey(x, y).SerializeUncompressed()
	} else {
		return marshal(publicKey.Curve, publicKey.X, publicKey.Y)
	}
}

type Unmarshaler interface {
	Unmarshal([]byte) (x, y *big.Int)
	UnmarshalCompressed([]byte) (x, y *big.Int)
}

// unmarshal converts a point, serialized by [marshal], into an x, y pair. It is
// an error if the point is not in uncompressed form, is not on the curve, or is
// the point at infinity. On error, x = nil.
func unmarshal(curve elliptic.Curve, data []byte) (x, y *big.Int) {
	if c, ok := curve.(Unmarshaler); ok {
		return c.Unmarshal(data)
	}

	byteLen := (curve.Params().BitSize + 7) / 8
	if len(data) != 1+2*byteLen {
		return nil, nil
	}
	if data[0] != 4 { // uncompressed form
		return nil, nil
	}
	p := curve.Params().P
	x = new(big.Int).SetBytes(data[1 : 1+byteLen])
	y = new(big.Int).SetBytes(data[1+byteLen:])
	if x.Cmp(p) >= 0 || y.Cmp(p) >= 0 {
		return nil, nil
	}
	if !curve.IsOnCurve(x, y) {
		return nil, nil
	}
	return
}

// marshal converts a point on the curve into the uncompressed form specified in
// SEC 1, Version 2.0, Section 2.3.3. If the point is not on the curve (or is
// the conventional point at infinity), the behavior is undefined.
func marshal(curve elliptic.Curve, x, y *big.Int) []byte {
	panicIfNotOnCurve(curve, x, y)

	byteLen := (curve.Params().BitSize + 7) / 8

	ret := make([]byte, 1+2*byteLen)
	ret[0] = 4 // uncompressed point

	x.FillBytes(ret[1 : 1+byteLen])
	y.FillBytes(ret[1+byteLen : 1+2*byteLen])

	return ret
}

func panicIfNotOnCurve(curve elliptic.Curve, x, y *big.Int) {
	// (0, 0) is the point at infinity by convention. It's ok to operate on it,
	// although IsOnCurve is documented to return false for it. See Issue 37294.
	if x.Sign() == 0 && y.Sign() == 0 {
		return
	}

	if !curve.IsOnCurve(x, y) {
		panic("crypto/elliptic: attempted operation on invalid point")
	}
}
