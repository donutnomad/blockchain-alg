package xed25519

import (
	"errors"
	"github.com/decred/dcrd/dcrec/edwards/v2"
	"github.com/donutnomad/blockchain-alg/xasn1"
)

var BadFormatPublicKeyErr = errors.New("bad format")

type PublicKey [32]byte

// ToCurve25519 Ed25519's PublicKey to Curve25519
func (pub PublicKey) ToCurve25519() (PublicKey, error) {
	return edwardsToMontgomery(pub)
}

// ToEd25519 Curve25519's PublicKey to Ed25519
func (pub PublicKey) ToEd25519() (out PublicKey) {
	res := montgomeryToEdwards(pub)
	copy(out[:], res)
	return out
}

// ToEd25519WithSig Curve25519's PublicKey to Ed25519 with last signature byte
func (pub PublicKey) ToEd25519WithSig(sigEndByte byte) PublicKey {
	res := pub.ToEd25519()
	res[31] &= 127
	res[31] |= sigEndByte & 128
	return res
}

func ParsePubKey(serialized [32]byte) (key PublicKey, err error) {
	pubKey, err := edwards.ParsePubKey(serialized[:])
	if err != nil {
		return PublicKey{}, err
	}
	return PublicKey(pubKey.Serialize()), nil
}

func ParsePubKeyASN1(bs []byte) (key PublicKey, err error) {
	k, err := xasn1.ParsePKIXPublicKey(bs)
	if err != nil {
		return PublicKey{}, err
	}
	serialized := k.PublicKey.Bytes
	if len(serialized) != 32 {
		return PublicKey{}, BadFormatPublicKeyErr
	}
	return ParsePubKey([32]byte(serialized))
}
