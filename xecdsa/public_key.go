package xecdsa

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding"
	"encoding/hex"
	"errors"
	"math/big"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/donutnomad/blockchain-alg/xsecp256k1"
	"github.com/donutnomad/blockchain-alg/xx509"
)

var InvalidPubKeyBytes = errors.New("invalid public key")

// PublicKey represents an ECDSA public key.
type PublicKey struct {
	elliptic.Curve
	X, Y *big.Int
}

// From Builder
func (p *PublicKey) From(pubKey any, alg Algorithm) (*PublicKey, error) {
	switch pub := pubKey.(type) {
	case PublicKey:
		return p.FromECDSA(p.ToECDSA()), nil
	case *PublicKey:
		return p.FromECDSA(p.ToECDSA()), nil
	case *ecdsa.PrivateKey:
		return p.FromECDSA(&pub.PublicKey), nil
	case ecdsa.PublicKey:
		return p.FromECDSA(&pub), nil
	case *ecdsa.PublicKey:
		return p.FromECDSA(pub), nil
	case *secp256k1.PublicKey:
		return p.FromECDSA(pub.ToECDSA()), nil
	case [33]byte:
		return p.FromBytes(pub[:], alg)
	case [65]byte:
		return p.FromBytes(pub[:], alg)
	case []byte:
		return p.FromBytes(pub, alg)
	case *[]byte:
		return p.FromBytes(*pub, alg)
	case string:
		if len(pub)%2 == 0 && pub[0] == '0' && (pub[1] == 'x' || pub[1] == 'X') {
			bs, err := hex.DecodeString(pub[2:])
			if err != nil {
				return nil, err
			}
			return p.FromBytes(bs, alg)
		}
		return p.FromBytes([]byte(pub), alg)
	case encoding.TextMarshaler:
		bytes, err := pub.MarshalText()
		if err != nil {
			return nil, err
		}
		return p.FromBytes(bytes, alg)
	case encoding.BinaryMarshaler:
		bytes, err := pub.MarshalBinary()
		if err != nil {
			return nil, err
		}
		return p.FromBytes(bytes, alg)
	default:
		return nil, KeyFormatNotSupported
	}
}

// FromBytes Builder
func (p *PublicKey) FromBytes(bs []byte, alg Algorithm) (*PublicKey, error) {
	if alg == Secp256k1 {
		key, err := xsecp256k1.ParsePubKey(bs)
		if err != nil {
			return nil, err
		}
		return p.FromECDSA(key.ToECDSA()), nil
	} else {
		if len(bs) == 0 {
			return nil, InvalidPubKeyBytes
		}
		if bs[0] == 4 { // uncompressed form
			x, y := unmarshal(alg.Curve(), bs)
			if x == nil || y == nil {
				return nil, InvalidPubKeyBytes
			}
			return &PublicKey{Curve: alg.Curve(), X: x, Y: y}, nil
		} else if bs[0] == 2 || bs[0] == 3 { // compressed
			x, y := elliptic.UnmarshalCompressed(alg.Curve(), bs)
			if x == nil || y == nil {
				return nil, InvalidPubKeyBytes
			}
			return &PublicKey{Curve: alg.Curve(), X: x, Y: y}, nil
		}
		return nil, InvalidPubKeyBytes
	}
}

// FromECDSA Builder
func (p *PublicKey) FromECDSA(pub *ecdsa.PublicKey) *PublicKey {
	return &PublicKey{
		Curve: pub.Curve,
		X:     new(big.Int).Set(pub.X),
		Y:     new(big.Int).Set(pub.Y),
	}
}

func (p *PublicKey) ToECDSA() *ecdsa.PublicKey {
	return &ecdsa.PublicKey{
		Curve: p.Curve,
		X:     new(big.Int).Set(p.X),
		Y:     new(big.Int).Set(p.Y),
	}
}

func (p *PublicKey) ToBytes() []byte {
	return p.Serialize(false)
}

func (p *PublicKey) ToDER() ([]byte, error) {
	var k = p.ToECDSA()
	return xx509.MarshalPKIXPublicKey(k)
}

func (p *PublicKey) Serialize(compressed bool) []byte {
	if compressed {
		return SerializeCompressed(p.ToECDSA())
	} else {
		return SerializeUncompressed(p.ToECDSA())
	}
}
