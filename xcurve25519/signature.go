package xcurve25519

func UniformSignature(pubEndByte byte, signature [64]byte) Signature {
	signature[63] &= 127              /*bbbbbbbb & 01111111 ==> clear first byte*/
	signature[63] |= pubEndByte & 128 /*endByte & 10000000 ==> keep the first byte when it is 0*/
	return signature
}
