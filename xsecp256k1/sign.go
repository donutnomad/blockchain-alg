package xsecp256k1

import (
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	secp_ecdsa "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"math/big"
)

// SignSecp256k1 generates an ECDSA signature over the secp256k1 curve for the provided
// hash (which should be the result of hashing a larger message) using the
// given private key. The produced signature is deterministic (same message and
// same key yield the same signature) and canonical in accordance with RFC6979
// and BIP0062.
func SignSecp256k1(key [32]byte, hash []byte) Signature {
	privKey := secp256k1.PrivKeyFromBytes(key[:])
	signature := secp_ecdsa.Sign(privKey, hash)
	return Signature{
		r: scalarToInt(signature.R()),
		s: scalarToInt(signature.S()),
	}
}

func SignSecp256k1Compact(key [32]byte, hash []byte) SignatureCompat {
	pri := secp256k1.PrivKeyFromBytes(key[:])
	signature := secp_ecdsa.SignCompact(pri, hash, false)
	return SignatureCompat{
		r: new(big.Int).SetBytes(signature[1:33]),
		s: new(big.Int).SetBytes(signature[33:65]),
		v: signature[0],
	}
}

// RecoverSecp256k1 attempts to recover the secp256k1 public key from the provided
// compact signature and message hash.
func RecoverSecp256k1(signature SignatureCompat, hash []byte) (*PublicKey, error) {
	array := signature.BytesVRS()
	compact, _, err := secp_ecdsa.RecoverCompact(array[:], hash)
	if err != nil {
		return nil, err
	}
	return &PublicKey{
		*compact,
	}, nil
}
