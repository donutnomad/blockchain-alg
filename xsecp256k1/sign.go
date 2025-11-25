package xsecp256k1

import (
	"math/big"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	secp_ecdsa "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
)

// SignS256 generates an ECDSA signature over the secp256k1 curve for the provided
// hash (which should be the result of hashing a larger message) using the
// given private key. The produced signature is deterministic (same message and
// same key yield the same signature) and canonical in accordance with RFC6979
// and BIP0062.
func SignS256(key [32]byte, hash []byte) Signature {
	privKey := secp256k1.PrivKeyFromBytes(key[:])
	signature := secp_ecdsa.Sign(privKey, hash)
	return Signature{
		r: scalarToInt(signature.R()),
		s: scalarToInt(signature.S()),
	}
}

// SignS256Compact generates a compact ECDSA signature over the secp256k1 curve.
// It returns a SignatureCompat containing R, S, and the recovery ID (v).
// The recovery ID allows public key recovery from the signature.
func SignS256Compact(key [32]byte, hash []byte) SignatureCompat {
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

// Ecrecover returns the uncompressed public key that created the given signature.
func Ecrecover(signature SignatureCompat, hash []byte) ([]byte, error) {
	pb, err := RecoverSecp256k1(signature, hash)
	if err != nil {
		return nil, err
	}
	return pb.SerializeUncompressed(), nil
}

// SigToPub recovers the public key from a compact signature and message hash.
// It is an alias for RecoverSecp256k1.
func SigToPub(signature SignatureCompat, hash []byte) (*PublicKey, error) {
	return RecoverSecp256k1(signature, hash)
}

// VerifySignature verifies an ECDSA signature using any type that implements
// the Signature() method. It extracts R and S from the signature and validates
// against the public key and message hash.
func VerifySignature[S interface {
	Signature() Signature
}](pubKey []byte, sig S, hash []byte) bool {
	sig_ := sig.Signature()
	return VerifyEthereumSignature(pubKey, sig_.R(), sig_.S(), hash)
}
