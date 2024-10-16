package xsecp256k1

import "github.com/decred/dcrd/dcrec/secp256k1/v4"

type PublicKey = secp256k1.PublicKey

func ParsePubKey(serialized []byte) (key *PublicKey, err error) {
	pubKey, err := secp256k1.ParsePubKey(serialized)
	if err != nil {
		return nil, err
	}
	return pubKey, nil
}
