package xcurve25519

import "github.com/donutnomad/blockchain-alg/xed25519"

func UniformSignature(pubEndByte byte, signature [64]byte) Signature {
	signature[63] &= 127              /*bbbbbbbb & 01111111 ==> clear first byte*/
	signature[63] |= pubEndByte & 128 /*endByte & 10000000 ==> keep the first byte when it is 0*/
	return signature
}

func ConvertEd25519PubKeyAndSig(pub xed25519.PublicKey, sig [64]byte) (pubCurve25519 PublicKey, _ Signature) {
	return pub.ToEd25519(), UniformSignature(pub[len(pub)-1], sig)
}
