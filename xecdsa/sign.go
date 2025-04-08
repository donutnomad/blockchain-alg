package xecdsa

import (
	"crypto/ecdsa"
	"crypto/rand"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	secpEcdsa "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"github.com/donutnomad/blockchain-alg/xsecp256k1"
	"io"
	"math/big"
)

func (p *PrivateKey) Sign(hash []byte, reader ...io.Reader) (ISignature, error) {
	var randReader = rand.Reader
	if len(reader) != 0 {
		randReader = reader[0]
	}
	if p.Algorithm() == Secp256k1 {
		pri := secp256k1.PrivKeyFromBytes(p.D.Bytes())
		signature := secpEcdsa.SignCompact(pri, hash, false)
		r := new(big.Int).SetBytes(signature[1:33])
		s := new(big.Int).SetBytes(signature[33:65])
		v := signature[0]
		return &RSVSignature{
			RSSignature: RSSignature{r, s},
			v:           v,
		}, nil
	} else {
		r, s, err := ecdsa.Sign(randReader, p.ToECDSA(), hash)
		if err != nil {
			return nil, err
		}
		return &RSSignature{r, s}, nil
	}
}

func Sign(pri *PrivateKey, hash []byte, reader ...io.Reader) (ISignature, error) {
	return pri.Sign(hash, reader...)
}

func Verify(publicKey *ecdsa.PublicKey, hash []byte, signature ISignature) bool {
	alg := Algorithm(0).FromCurve(publicKey.Curve)
	if alg == Secp256k1 {
		unCompressKey := SerializeUncompressed(publicKey)
		return xsecp256k1.VerifyEthereumSignature(unCompressKey, signature.R(), signature.S(), hash)
	} else {
		return ecdsa.Verify(publicKey, hash, signature.R(), signature.S())
	}
}
