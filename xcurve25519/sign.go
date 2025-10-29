package xcurve25519

import (
	"crypto/ed25519"

	"filippo.io/edwards25519"
	"github.com/donutnomad/blockchain-alg/internal/hashs"
	"github.com/donutnomad/blockchain-alg/xed25519"
	"github.com/samber/lo"
)

type PublicKey = xed25519.PublicKey

const SignatureSize = 64

type Signature [SignatureSize]byte

func Sign(priKey [32]byte, message []byte, random []byte) [64]byte {
	priKey[0] &= 248
	priKey[31] &= 127
	priKey[31] |= 64
	var ed25519PriKey = priKey
	var ed25519PubKey = scalarBaseMult(ed25519PriKey)
	var nonce = generateNonce(ed25519PriKey, message, random)
	var signature = xed25519.SignFromScalar(ed25519PriKey, ed25519PubKey, nonce, message, "", "")
	return UniformSignature(ed25519PubKey[31], signature)
}

func Verify(pubCurve25519 PublicKey, message []byte, sig [64]byte) bool {
	return VerifyByEd25519(pubCurve25519.ToEd25519WithSig(sig[63]), message, sig)
}

// SignByEd25519 signs a message using an Ed25519 private key and converts the resulting signature to Curve25519 format.
func SignByEd25519(priEd25519 ed25519.PrivateKey, message []byte) Signature {
	signature := xed25519.Sign(priEd25519[:], message)
	return UniformSignature(priEd25519[63], [64]byte(signature))
}

func VerifyByEd25519(pubEd25519 xed25519.PublicKey, message []byte, sig Signature) bool {
	orig := sig[63]
	defer func() {
		sig[63] = orig
	}()
	sig[63] &= 127
	return ed25519.Verify(pubEd25519[:], message, sig[:])
}

func GenPubKey(pri [32]byte) [32]byte {
	return scalarBaseMultMontgomery(pri)
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

func scalarBaseMultMontgomery(v [32]byte) [32]byte {
	scalar := lo.Must1(edwards25519.NewScalar().SetBytesWithClamping(v[:]))
	return [32]byte(new(edwards25519.Point).ScalarBaseMult(scalar).BytesMontgomery())
}

func mod(v [64]byte) (*edwards25519.Scalar, [32]byte) {
	scalar := lo.Must1(edwards25519.NewScalar().SetUniformBytes(v[:]))
	return scalar, [32]byte(scalar.Bytes())
}
