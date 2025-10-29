package xasn1

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math"
	"math/big"

	"github.com/samber/lo"
	"golang.org/x/crypto/cryptobyte"
	asn11 "golang.org/x/crypto/cryptobyte/asn1"
)

// A StructuralError suggests that the ASN.1 data is valid, but the Go type
// which is receiving it doesn't match.
type StructuralError = asn1.StructuralError

// A SyntaxError suggests that the ASN.1 data is invalid.
type SyntaxError = asn1.SyntaxError

// ParseBase128Int parses a base-128 encoded int from the given offset in the
// given byte slice. It returns the value and the new offset.
func ParseBase128Int(bytes []byte, initOffset int) (ret, offset int, err error) {
	offset = initOffset
	var ret64 int64
	for shifted := 0; offset < len(bytes); shifted++ {
		// 5 * 7 bits per byte == 35 bits of data
		// Thus the representation is either non-minimal or too large for an int32
		if shifted == 5 {
			err = StructuralError{Msg: "base 128 integer too large"}
			return
		}
		ret64 <<= 7
		b := bytes[offset]
		// integers should be minimally encoded, so the leading octet should
		// never be 0x80
		if shifted == 0 && b == 0x80 {
			err = SyntaxError{Msg: "integer is not minimally encoded"}
			return
		}
		ret64 |= int64(b & 0x7f)
		offset++
		if b&0x80 == 0 {
			ret = int(ret64)
			// Ensure that the returned value fits in an int on all platforms
			if ret64 > math.MaxInt32 {
				err = StructuralError{Msg: "base 128 integer too large"}
			}
			return
		}
	}
	err = SyntaxError{Msg: "truncated base 128 integer"}
	return
}

type TagAndLength struct {
	Class, Tag, Length int
	IsCompound         bool
}

// ParseTagAndLength parses an ASN.1 tag and length pair from the given offset
// into a byte slice. It returns the parsed data and the new offset. SET and
// SET OF (tag 17) are mapped to SEQUENCE and SEQUENCE OF (tag 16) since we
// don't distinguish between ordered and unordered objects in this code.
func ParseTagAndLength(bytes []byte, initOffset int) (ret TagAndLength, offset int, err error) {
	offset = initOffset
	// parseTagAndLength should not be called without at least a single
	// byte to read. Thus this check is for robustness:
	if offset >= len(bytes) {
		err = errors.New("asn1: internal error in parseTagAndLength")
		return
	}
	b := bytes[offset]
	offset++
	ret.Class = int(b >> 6)
	ret.IsCompound = b&0x20 == 0x20
	ret.Tag = int(b & 0x1f)

	// If the bottom five bits are set, then the tag number is actually base 128
	// encoded afterwards
	if ret.Tag == 0x1f {
		ret.Tag, offset, err = ParseBase128Int(bytes, offset)
		if err != nil {
			return
		}
		// Tags should be encoded in minimal form.
		if ret.Tag < 0x1f {
			err = SyntaxError{Msg: "non-minimal tag"}
			return
		}
	}
	if offset >= len(bytes) {
		err = SyntaxError{Msg: "truncated tag or length"}
		return
	}
	b = bytes[offset]
	offset++
	if b&0x80 == 0 {
		// The length is encoded in the bottom 7 bits.
		ret.Length = int(b & 0x7f)
	} else {
		// Bottom 7 bits give the number of length bytes to follow.
		numBytes := int(b & 0x7f)
		if numBytes == 0 {
			err = SyntaxError{Msg: "indefinite length found (not DER)"}
			return
		}
		ret.Length = 0
		for i := 0; i < numBytes; i++ {
			if offset >= len(bytes) {
				err = SyntaxError{Msg: "truncated tag or length"}
				return
			}
			b = bytes[offset]
			offset++
			if ret.Length >= 1<<23 {
				// We can't shift ret.length up without
				// overflowing.
				err = StructuralError{Msg: "length too large"}
				return
			}
			ret.Length <<= 8
			ret.Length |= int(b)
			if ret.Length == 0 {
				// DER requires that lengths be minimal.
				err = StructuralError{Msg: "superfluous leading zeros in length"}
				return
			}
		}
		// Short lengths must be encoded in short form.
		if ret.Length < 0x80 {
			err = StructuralError{Msg: "non-minimal length"}
			return
		}
	}

	return
}

func ParseObjectIdentifier(bytes []byte) (s []int, err error) {
	if len(bytes) == 0 {
		panic("zero length OBJECT IDENTIFIER")
	}

	// In the worst case, we get two elements from the first byte (which is
	// encoded differently) and then every varint is a single byte long.
	s = make([]int, len(bytes)+1)

	// The first varint is 40*value1 + value2:
	// According to this packing, value1 can take the values 0, 1 and 2 only.
	// When value1 = 0 or value1 = 1, then value2 is <= 39. When value1 = 2,
	// then there are no restrictions on value2.
	v, offset, err := ParseBase128Int(bytes, 0)
	if err != nil {
		return
	}
	if v < 80 {
		s[0] = v / 40
		s[1] = v % 40
	} else {
		s[0] = 2
		s[1] = v - 80
	}

	i := 2
	for ; offset < len(bytes); i++ {
		v, offset, err = ParseBase128Int(bytes, offset)
		if err != nil {
			return
		}
		s[i] = v
	}
	s = s[0:i]
	return
}

func FindTypeList(bs []byte, offset int, target int) [][]byte {
	var out [][]byte
	for i := offset; i < len(bs); {
		ret, ni, err := ParseTagAndLength(bs, i)
		if err != nil {
			return nil
		}
		i = ni
		if ret.Tag == target {
			out = append(out, bs[i:i+ret.Length])
		} else if ret.Tag == asn1.TagSequence {
			if ret := FindTypeList(bs, i, target); len(ret) > 0 {
				out = append(out, ret...)
			}
		}
		i += ret.Length
	}
	return out
}

func FindOids(bs []byte) []asn1.ObjectIdentifier {
	var oids = FindTypeList(bs, 0, asn1.TagOID)
	return lo.FilterMap(oids, func(item []byte, index int) (asn1.ObjectIdentifier, bool) {
		identifier, err := ParseObjectIdentifier(item)
		if err != nil {
			return nil, false
		}
		return identifier, true
	})
}

type PublicKeyInfo struct {
	Raw       asn1.RawContent
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

// ParsePKIXPublicKey x509.ParsePKIXPublicKey
func ParsePKIXPublicKey(bs []byte) (*PublicKeyInfo, error) {
	var pki PublicKeyInfo
	if rest, err := asn1.Unmarshal(bs, &pki); err != nil {
		return nil, errors.New("x509: failed to parse public key (use ParsePKCS1PublicKey instead for this key format)")
	} else if len(rest) != 0 {
		return nil, errors.New("x509: trailing data after ASN.1 of public-key")
	}
	return &pki, nil
}

func ParseSignatureRS(bs []byte) (r []byte, s []byte, _ error) {
	var inner cryptobyte.String
	input := cryptobyte.String(bs)
	if !input.ReadASN1(&inner, asn11.SEQUENCE) ||
		!input.Empty() ||
		!inner.ReadASN1Integer(&r) ||
		!inner.ReadASN1Integer(&s) ||
		!inner.Empty() {
		return nil, nil, errors.New("invalid ASN.1")
	}
	return padSliceLeft(r, 32), padSliceLeft(s, 32), nil
}

func ParseSignatureRSSlice(bs []byte) ([64]byte, error) {
	r, s, err := ParseSignatureRS(bs)
	if err != nil {
		return [64]byte{}, err
	}
	var out [64]byte
	copy(out[0:32], r)
	copy(out[32:64], s)
	return out, nil
}

func MarshalAsn1SignatureRS(r, s []byte) []byte {
	var b cryptobyte.Builder
	b.AddASN1(asn11.SEQUENCE, func(child *cryptobyte.Builder) {
		child.AddASN1BigInt(new(big.Int).SetBytes(r))
		child.AddASN1BigInt(new(big.Int).SetBytes(s))
	})
	return b.BytesOrPanic()
}

func MarshalAsn1SignatureSlice(bs [64]byte) []byte {
	return MarshalAsn1SignatureRS(bs[0:32], bs[32:64])
}

func padSliceLeft(bs []byte, size int) []byte {
	if len(bs) >= size {
		return bs[:size]
	}
	var out = make([]byte, size)
	copy(out[size-len(bs):], bs[:])
	return out
}
