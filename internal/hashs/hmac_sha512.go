package hashs

import (
	"crypto/hmac"
	"crypto/sha512"
)

func HmacSha512(key []byte, messages ...[]byte) (out [64]byte) {
	h := hmac.New(sha512.New, key)
	for _, message := range messages {
		h.Write(message)
	}
	return ([64]byte)(h.Sum(nil))
}
