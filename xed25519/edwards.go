package xed25519

import (
	edwardsF "filippo.io/edwards25519"
	"filippo.io/edwards25519/field"
)

var one = new(field.Element).One()

func edwardsToMontgomery(publicKey [32]byte) (out [32]byte, _ error) {
	A, err := new(edwardsF.Point).SetBytes(publicKey[:])
	if err != nil {
		return [32]byte{}, err
	}
	_, Y, _, _ := A.ExtendedCoordinates()

	// We only need the x-coordinate of the curve25519 point, which I'll
	// call u. The isomorphism is u=(y+1)/(1-y), since y=Y/Z, this gives
	// u=(Y+Z)/(Z-Y). We know that Z=1, thus u=(Y+1)/(1-Y).
	oneMinusY := new(field.Element).Subtract(one, Y)
	yPlusOne := new(field.Element).Add(Y, one)
	invOneMinusY := new(field.Element).Invert(oneMinusY)
	// u=(Y+1)/(1-Y) = (Y+1)*(1-Y)^-1 = (Y+1)*Inv(1-Y)
	u := new(field.Element).Multiply(yPlusOne, invOneMinusY)
	copy(out[:], u.Bytes())

	return out, nil
}

func montgomeryToEdwards(publicKey [32]byte) []byte {
	x, err := new(field.Element).SetBytes(publicKey[:])
	if err != nil {
		panic(err)
	}
	xMinusOne := new(field.Element).Subtract(x, one)
	xPlusOne := new(field.Element).Add(x, one)
	invXPlusOne := new(field.Element).Invert(xPlusOne)
	y := new(field.Element).Multiply(xMinusOne, invXPlusOne)

	pk := y.Bytes()
	return pk
}
