package xecdsa

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding"
	"encoding/hex"
	"errors"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"io"
	"math/big"
	"reflect"
)

var KeyInvalid = errors.New("invalid key")
var KeyFormatNotSupported = errors.New("key format not supported")

type Key *big.Int

type PrivateKey struct {
	ecdsa.PublicKey
	D *big.Int
}

func GenerateKey(alg Algorithm, reader ...io.Reader) (*PrivateKey, error) {
	var randReader = rand.Reader
	if len(reader) != 0 {
		randReader = reader[0]
	}
	if alg == Secp256k1 {
		k, err := secp256k1.GeneratePrivateKeyFromRand(randReader)
		if err != nil {
			return nil, err
		}
		return new(PrivateKey).FromModNScalar(k.Key), nil
	} else {
		return new(PrivateKey).FromECDSA2(ecdsa.GenerateKey(alg.Curve(), randReader))
	}
}

func NewPrivateKeyS256(key [32]byte) (*PrivateKey, error) {
	return new(PrivateKey).FromBytes(key[:], Secp256k1)
}

func NewPrivateKeyP256(key [32]byte) (*PrivateKey, error) {
	return new(PrivateKey).FromBytes(key[:], P256)
}

// From Builder
func (p *PrivateKey) From(key any, alg Algorithm) (*PrivateKey, error) {
	switch t := key.(type) {
	case *ecdsa.PrivateKey:
		return &PrivateKey{
			PublicKey: ecdsa.PublicKey{
				Curve: t.PublicKey.Curve,
				X:     new(big.Int).Set(t.PublicKey.X),
				Y:     new(big.Int).Set(t.PublicKey.Y),
			},
			D: new(big.Int).Set(t.D),
		}, nil
	case string:
		if len(t)%2 == 0 && t[0] == '0' && (t[1] == 'x' || t[1] == 'X') {
			bs, err := hex.DecodeString(t[2:])
			if err != nil {
				return nil, err
			}
			return new(PrivateKey).FromBytes(bs, alg)
		}
		return new(PrivateKey).FromBytes([]byte(t), alg)
	case *secp256k1.PrivateKey:
		return new(PrivateKey).FromModNScalar(t.Key), nil
	case *big.Int:
		return new(PrivateKey).FromBigInt(t, alg)
	case []byte:
		return new(PrivateKey).FromBytes(t[:], alg)
	case *[]byte:
		return new(PrivateKey).FromBytes((*t)[:], alg)
	case uint:
		return new(PrivateKey).FromBigInt(big.NewInt(int64(t)), alg)
	case uint8:
		return new(PrivateKey).FromBigInt(big.NewInt(int64(t)), alg)
	case uint16:
		return new(PrivateKey).FromBigInt(big.NewInt(int64(t)), alg)
	case uint32:
		return new(PrivateKey).FromBigInt(big.NewInt(int64(t)), alg)
	case uint64:
		return new(PrivateKey).FromBigInt(big.NewInt(int64(t)), alg)
	case int:
		return new(PrivateKey).FromBigInt(big.NewInt(int64(t)), alg)
	case int8:
		return new(PrivateKey).FromBigInt(big.NewInt(int64(t)), alg)
	case int16:
		return new(PrivateKey).FromBigInt(big.NewInt(int64(t)), alg)
	case int32:
		return new(PrivateKey).FromBigInt(big.NewInt(int64(t)), alg)
	case int64:
		return new(PrivateKey).FromBigInt(big.NewInt(t), alg)
	case encoding.TextMarshaler:
		bytes, err := t.MarshalText()
		if err != nil {
			return nil, err
		}
		return new(PrivateKey).FromBytes(bytes, alg)
	case encoding.BinaryMarshaler:
		bytes, err := t.MarshalBinary()
		if err != nil {
			return nil, err
		}
		return new(PrivateKey).FromBytes(bytes, alg)
	}

	v := reflect.ValueOf(key)
	if v.Kind() == reflect.Array && v.Type().Elem().Kind() == reflect.Uint8 {
		length := v.Len()
		bytes := make([]byte, length)
		for i := 0; i < length; i++ {
			bytes[i] = uint8(v.Index(i).Uint())
		}
		return new(PrivateKey).FromBytes(bytes, alg)
	}
	return nil, KeyFormatNotSupported
}

// FromBytes Builder
func (p *PrivateKey) FromBytes(key []byte, alg Algorithm) (*PrivateKey, error) {
	return p.FromBigInt(new(big.Int).SetBytes(key), alg)
}

// FromBigInt Builder
func (p *PrivateKey) FromBigInt(key *big.Int, alg Algorithm) (*PrivateKey, error) {
	curve := alg.Curve()
	D := new(big.Int).Set(key)
	if D.Cmp(big.NewInt(1)) < 0 || D.Cmp(curve.Params().N) >= 0 {
		return nil, KeyInvalid
	}
	x, y := curve.ScalarBaseMult(D.Bytes())
	return &PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: curve,
			X:     x,
			Y:     y,
		},
		D: D,
	}, nil
}

// FromECDSA Builder
func (p *PrivateKey) FromECDSA(pri *ecdsa.PrivateKey) *PrivateKey {
	ret := PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: pri.Curve,
			X:     new(big.Int).Set(pri.X),
			Y:     new(big.Int).Set(pri.Y),
		},
		D: new(big.Int).Set(pri.D),
	}
	*p = ret
	return &ret
}

// FromECDSA2 Builder
func (p *PrivateKey) FromECDSA2(pri *ecdsa.PrivateKey, err error) (*PrivateKey, error) {
	if err != nil {
		return nil, err
	}
	return p.FromECDSA(pri), nil
}

// FromModNScalar Builder
func (p *PrivateKey) FromModNScalar(scalar secp256k1.ModNScalar) *PrivateKey {
	D := scalarToInt(scalar)
	ret, _ := p.FromBigInt(D, Secp256k1)
	*p = *ret
	return ret
}

func (p *PrivateKey) ToECDSA() *ecdsa.PrivateKey {
	return &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: p.Curve,
			X:     new(big.Int).Set(p.X),
			Y:     new(big.Int).Set(p.Y),
		},
		D: new(big.Int).Set(p.D),
	}
}

func (p *PrivateKey) ToDER() ([]byte, error) {
	var k = p.ToECDSA()
	return x509.MarshalPKCS8PrivateKey(k)
}

func (p *PrivateKey) Algorithm() Algorithm {
	return Algorithm(0).FromCurve(p.Curve)
}
