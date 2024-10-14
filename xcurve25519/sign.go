package xcurve25519

import (
	"crypto/ed25519"
	"filippo.io/edwards25519"
	"github.com/donutnomad/blockchain-alg/internal/hashs"
	"github.com/donutnomad/blockchain-alg/xed25519"
	"github.com/samber/lo"
	"strconv"
)

type PublicKey []byte

const SignatureSize = 64

type Signature [SignatureSize]byte

func Sign(priKey [32]byte, message []byte, random []byte) [64]byte {
	priKey[0] &= 248
	priKey[31] &= 127
	priKey[31] |= 64

	pubBs := scalarBaseMult(priKey)
	signature := xed25519.SignFromScalar(priKey, pubBs, generateNonce(priKey, message, random), message, "", "")
	return UniformSignature(pubBs[31], signature)
}

func Verify(pubCurve25519 PublicKey, message, sig []byte) bool {
	if l := len(pubCurve25519); l != ed25519.PublicKeySize {
		panic("ed25519: bad public key length: " + strconv.Itoa(l))
	}
	if len(sig) != ed25519.SignatureSize {
		return false
	}
	sig[63] &= 127
	return ed25519.Verify(ed25519.PublicKey(pubCurve25519), message, sig)
}

// SignByEd25519 signs a message using an Ed25519 private key and converts the resulting signature to Curve25519 format.
func SignByEd25519(priEd25519 ed25519.PrivateKey, message []byte) Signature {
	pubEd25519 := priEd25519[32:64]
	signature := [64]byte(xed25519.Sign(priEd25519[:], message))
	return UniformSignature(pubEd25519[31], signature)
}

// VerifyByEd25519 verifies a message signature using an Ed25519 public key.
// It checks if the provided signature, which is in Curve25519 format, is valid for the given message.
func VerifyByEd25519(pubEd25519 ed25519.PublicKey, message []byte, sig Signature) bool {
	if l := len(pubEd25519); l != ed25519.PublicKeySize {
		panic("ed25519: bad public key length: " + strconv.Itoa(l))
	}
	sig[63] &= 127
	return ed25519.Verify(pubEd25519[:], message, sig[:])
}

var magic = [32]byte{0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}

// signs a message 'hash' using the given private scalar priv.
// It uses RFC6979 to generate a deterministic nonce. Considered experimental.
// r = kG, where k is the RFC6979 nonce
// s = r + hash512(k || A || M) * a
func generateNonce(privateKey [32]byte, hash []byte, random []byte) (nonce [32]byte) {
	pre := hashs.SHA512(magic[:], privateKey[:], hash, random)
	_, nonce = mod(pre)
	return
}

func scalarBaseMult(v [32]byte) [32]byte {
	scalar := lo.Must1(edwards25519.NewScalar().SetBytesWithClamping(v[:]))
	return [32]byte(new(edwards25519.Point).ScalarBaseMult(scalar).Bytes())
}

func mod(v [64]byte) (*edwards25519.Scalar, [32]byte) {
	scalar := lo.Must1(edwards25519.NewScalar().SetUniformBytes(v[:]))
	return scalar, [32]byte(scalar.Bytes())
}
