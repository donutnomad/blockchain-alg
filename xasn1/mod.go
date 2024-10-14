package xasn1

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math"
)

// ParseBase128Int parses a base-128 encoded int from the given offset in the
// given byte slice. It returns the value and the new offset.
func ParseBase128Int(bytes []byte, initOffset int) (ret, offset int, err error) {
	offset = initOffset
	var ret64 int64
	for shifted := 0; offset < len(bytes); shifted++ {
		// 5 * 7 bits per byte == 35 bits of data
		// Thus the representation is either non-minimal or too large for an int32
		if shifted == 5 {
			panic("base 128 integer too large")
			return
		}
		ret64 <<= 7
		b := bytes[offset]
		// integers should be minimally encoded, so the leading octet should
		// never be 0x80
		if shifted == 0 && b == 0x80 {
			panic("\"integer is not minimally encoded\"")
			return
		}
		ret64 |= int64(b & 0x7f)
		offset++
		if b&0x80 == 0 {
			ret = int(ret64)
			// Ensure that the returned value fits in an int on all platforms
			if ret64 > math.MaxInt32 {
				panic("base 128 integer too large")
			}
			return
		}
	}
	panic("base 128 integer too large")
	return
}

func ParseObjectIdentifier(bytes []byte) (s []int, err error) {
	if len(bytes) == 0 {
		panic("zero length OBJECT IDENTIFIER")
		return
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

type publicKeyInfo struct {
	Raw       asn1.RawContent
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

// ParsePKIXPublicKey x509.ParsePKIXPublicKey
func ParsePKIXPublicKey(bs []byte) ([]byte, error) {
	var pki publicKeyInfo
	if rest, err := asn1.Unmarshal(bs, &pki); err != nil {
		return nil, errors.New("x509: failed to parse public key (use ParsePKCS1PublicKey instead for this key format)")
	} else if len(rest) != 0 {
		return nil, errors.New("x509: trailing data after ASN.1 of public-key")
	}
	return pki.PublicKey.Bytes, nil
}
