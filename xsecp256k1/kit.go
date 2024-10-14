package xsecp256k1

import (
	"errors"
	secp_ecdsa "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"github.com/donutnomad/blockchain-alg/xasn1"
	"math/big"
)

var BadFormatPublicKeyErr = errors.New("bad format")

var Secp256k1 = new(secp256k1Kit)

type secp256k1Kit struct {
}

func (k *secp256k1Kit) Sign(key [32]byte, hash []byte) SignatureCompat {
	return SignSecp256k1Compact(key, hash)
}

func (k *secp256k1Kit) SignANS1(asn1Key []byte, hash []byte) (SignatureCompat, error) {
	key, err := xasn1.ParsePKIXPublicKey(asn1Key)
	if err != nil {
		return SignatureCompat{}, err
	}
	if len(key) != 32 {
		return SignatureCompat{}, BadFormatPublicKeyErr
	}
	return k.Sign([32]byte(key), hash), nil
}

func (k *secp256k1Kit) VerifySignatureRS(pubKey []byte, rBig, sBig *big.Int, hash []byte) bool {
	return VerifyEthereumSignature(pubKey, rBig, sBig, hash)
}

func (k *secp256k1Kit) VerifySignature(pubKey []byte, sig interface{ Signature() Signature }, hash []byte) bool {
	sig_ := sig.Signature()
	return VerifyEthereumSignature(pubKey, sig_.R(), sig_.S(), hash)
}

func (k *secp256k1Kit) RecoverPublicKey(signature SignatureCompat, hash []byte) (*PublicKey, error) {
	return RecoverSecp256k1(signature, hash)
}

func (k *secp256k1Kit) FillSignatureV(publicKey *PublicKey, signature Signature, hash []byte) (SignatureCompat, bool) {
	v, ok := k.ExtractV(publicKey, signature, hash)
	if !ok {
		return SignatureCompat{}, false
	}
	return NewSignatureCompatWith(signature, v), true
}

func (k *secp256k1Kit) ExtractV(publicKey *PublicKey, signature Signature, hash []byte) (v byte, ok bool) {
	var full [65]byte
	copy(full[1:65], signature.Bytes())
	for i := byte(0); i < 2; i++ {
		full[0] = i
		compact, _, err := secp_ecdsa.RecoverCompact(full[:], hash)
		if err != nil {
			return 0, false
		}
		if compact.X().Cmp(publicKey.X()) == 0 && compact.Y().Cmp(publicKey.Y()) == 0 {
			return i, true
		}
	}
	return 0, false
}
