package xsecp256k1

import (
	"errors"
	"math/big"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	secp_ecdsa "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"github.com/donutnomad/blockchain-alg/xasn1"
)

// BadFormatPublicKeyErr is returned when the public key format is invalid.
var BadFormatPublicKeyErr = errors.New("bad format")

// Secp256k1 is a singleton instance providing secp256k1 cryptographic operations.
var Secp256k1 = new(secp256k1Kit)

// secp256k1Kit provides a collection of secp256k1 elliptic curve cryptographic utilities
// for signing, verification, and public key recovery operations.
type secp256k1Kit struct {
}

// Sign creates a compact signature for the given hash using the provided 32-byte private key.
// It returns a SignatureCompat containing the signature with recovery ID.
func (k *secp256k1Kit) Sign(key [32]byte, hash []byte) SignatureCompat {
	return SignS256Compact(key, hash)
}

// SignANS1 creates a compact signature using an ASN.1/DER encoded private key.
// It parses the ASN.1 key, extracts the 32-byte private key, and signs the hash.
// Returns an error if the key format is invalid or not 32 bytes.
func (k *secp256k1Kit) SignANS1(asn1Key []byte, hash []byte) (SignatureCompat, error) {
	key, err := xasn1.ParsePKIXPublicKey(asn1Key)
	if err != nil {
		return SignatureCompat{}, err
	}
	bs := key.PublicKey.Bytes
	if len(bs) != 32 {
		return SignatureCompat{}, BadFormatPublicKeyErr
	}
	return k.Sign([32]byte(bs), hash), nil
}

// VerifySignatureRS verifies an ECDSA signature given the R and S components as big integers.
// It returns true if the signature is valid for the given public key and hash.
func (k *secp256k1Kit) VerifySignatureRS(pubKey []byte, rBig, sBig *big.Int, hash []byte) bool {
	return VerifyEthereumSignature(pubKey, rBig, sBig, hash)
}

// VerifySignature verifies an ECDSA signature using any type that implements the Signature() method.
// It extracts R and S from the signature and validates against the public key and hash.
func (k *secp256k1Kit) VerifySignature(pubKey []byte, sig interface{ Signature() Signature }, hash []byte) bool {
	return VerifySignature(pubKey, sig, hash)
}

// RecoverPublicKey recovers the public key from a compact signature and message hash.
// The signature must include a valid recovery ID (v) for successful recovery.
func (k *secp256k1Kit) RecoverPublicKey(signature SignatureCompat, hash []byte) (*PublicKey, error) {
	return RecoverSecp256k1(signature, hash)
}

// FillSignatureV computes and fills the recovery ID (v) for a signature.
// It attempts to recover the correct v value by comparing against the provided public key.
// Returns the complete SignatureCompat with v and true if successful, or empty and false otherwise.
func (k *secp256k1Kit) FillSignatureV(publicKey *PublicKey, signature Signature, hash []byte) (SignatureCompat, bool) {
	v, ok := k.ExtractV(publicKey, signature, hash)
	if !ok {
		return SignatureCompat{}, false
	}
	return NewSignatureCompatWith(signature, v), true
}

// ExtractV extracts the recovery ID (v) from a signature by attempting to recover
// the public key and comparing it with the provided public key.
// It returns the recovery ID (27 or 28) and true if successful, or 0 and false otherwise.
func (k *secp256k1Kit) ExtractV(publicKey *PublicKey, signature Signature, hash []byte) (v byte, ok bool) {
	N := secp256k1.S256().N
	halfN := new(big.Int).Rsh(N, 1) // N / 2

	var full [65]byte
	copy(full[1:65], signature.Bytes()) // R || S

	sBig := new(big.Int).SetBytes(full[33:65])

	// Canonical S / Low-S normalization
	// Ethereum requires S to be at most half of the curve order to prevent signature malleability attacks.
	if sBig.Cmp(halfN) > 0 {
		sBig.Sub(N, sBig) // S = N - S
		sBig.FillBytes(full[33:65])
	}

	// Try both recovery IDs (27 and 28) to find the one that recovers the correct public key.
	for i := byte(27); i <= 28; i++ {
		full[0] = i
		compact, _, err := secp_ecdsa.RecoverCompact(full[:], hash)
		if err != nil {
			continue
		}
		if compact.IsEqual(&publicKey.PublicKey) {
			return i, true
		}
	}
	return 0, false
}
