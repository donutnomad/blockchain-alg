package xsecp256k1

import (
	"crypto/ecdsa"
	"encoding/hex"
	"errors"
	"hash"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"golang.org/x/crypto/sha3"
)

// ErrInvalidPublicKey is returned when the public key type is not supported.
var ErrInvalidPublicKey = errors.New("invalid public key")

// Address represents a 20-byte Ethereum address.
type Address [20]byte

// Hex returns an EIP55-compliant hex string representation of the address.
func (a Address) Hex() string {
	return string(a.checksumHex())
}

// String implements fmt.Stringer.
func (a Address) String() string {
	return a.Hex()
}

// checksumHex computes the EIP55 checksum hex encoding of the address.
func (a *Address) checksumHex() []byte {
	var buf [len(a)*2 + 2]byte
	copy(buf[:2], "0x")
	hex.Encode(buf[2:], a[:])

	// compute checksum
	sha := sha3.NewLegacyKeccak256()
	sha.Write(buf[2:])
	hashBs := sha.Sum(nil)

	for i := 2; i < len(buf); i++ {
		hashByte := hashBs[(i-2)/2]
		if i%2 == 0 {
			hashByte = hashByte >> 4
		} else {
			hashByte &= 0xf
		}
		if buf[i] > '9' && hashByte > 7 {
			buf[i] -= 32
		}
	}
	return buf[:]
}

// PublicKey wraps a secp256k1 public key with additional utility methods.
type PublicKey struct {
	secp256k1.PublicKey
}

// Address derives the Ethereum address from the public key.
// It computes the Keccak256 hash of the uncompressed public key (without the 0x04 prefix)
// and returns the last 20 bytes.
func (p *PublicKey) Address() Address {
	bs := p.PublicKey.SerializeUncompressed()
	return Address(Keccak256(bs[1:])[12:])
}

// NewPublicKeyFromEcdsa creates a PublicKey from a standard library ecdsa.PublicKey.
func NewPublicKeyFromEcdsa(p *ecdsa.PublicKey) *PublicKey {
	x := new(secp256k1.FieldVal)
	y := new(secp256k1.FieldVal)
	x.SetByteSlice(p.X.Bytes())
	y.SetByteSlice(p.Y.Bytes())
	return &PublicKey{
		PublicKey: *secp256k1.NewPublicKey(x, y),
	}
}

// ParsePubKey parses a serialized public key in compressed (33 bytes) or uncompressed (65 bytes) format.
func ParsePubKey(serialized []byte) (key *PublicKey, err error) {
	pubKey, err := secp256k1.ParsePubKey(serialized)
	if err != nil {
		return nil, err
	}
	return &PublicKey{
		PublicKey: *pubKey,
	}, nil
}

// DecompressPubkey parses a public key in the 33-byte compressed format.
// It is an alias for ParsePubKey.
func DecompressPubkey(serialized []byte) (key *PublicKey, err error) {
	return ParsePubKey(serialized)
}

// CompressPubkey serializes a public key in the 33-byte compressed format.
func CompressPubkey(pub *PublicKey) []byte {
	return pub.SerializeCompressed()
}

// PubkeyToAddress converts a public key to an Ethereum address.
// It accepts multiple public key types: *PublicKey, *ecdsa.PublicKey, *secp256k1.PublicKey,
// []byte (serialized), or string (hex encoded).
func PubkeyToAddress[T *PublicKey | *ecdsa.PublicKey | *secp256k1.PublicKey | []byte | string](pub T) (Address, error) {
	return PubToAddress(pub)
}

// PubToAddress converts a public key to an Ethereum address.
// It accepts multiple public key types: *PublicKey, *ecdsa.PublicKey, *secp256k1.PublicKey,
// []byte (serialized), or string (hex encoded).
func PubToAddress[T *PublicKey | *ecdsa.PublicKey | *secp256k1.PublicKey | []byte | string](pub T) (Address, error) {
	var bytesToAddress = func(bs []byte) (Address, error) {
		key, err := ParsePubKey(bs)
		if err != nil {
			return Address{}, err
		}
		return key.Address(), nil
	}

	switch t := any(pub).(type) {
	case *PublicKey:
		return t.Address(), nil
	case *ecdsa.PublicKey:
		return NewPublicKeyFromEcdsa(t).Address(), nil
	case *secp256k1.PublicKey:
		key := &PublicKey{PublicKey: *t}
		return key.Address(), nil
	case []byte:
		return bytesToAddress(t)
	case string:
		// decode hex
		if len(t) >= 2 && t[0] == '0' && (t[1] == 'x' || t[1] == 'X') {
			t = t[2:]
			bs, err := hex.DecodeString(t[2:])
			if err != nil {
				return Address{}, err
			}
			return bytesToAddress(bs)
		}
		// string as bytes
		return bytesToAddress([]byte(t))
	default:
		return Address{}, ErrInvalidPublicKey
	}
}

// Keccak256 calculates and returns the Keccak256 hash of the input data.
func Keccak256(data ...[]byte) []byte {
	b := make([]byte, 32)
	d := sha3.NewLegacyKeccak256().(KeccakState)
	for _, b := range data {
		d.Write(b)
	}
	d.Read(b)
	return b
}

// KeccakState wraps sha3.state, providing both hash.Hash and Read capabilities.
type KeccakState interface {
	hash.Hash
	Read([]byte) (int, error)
}
