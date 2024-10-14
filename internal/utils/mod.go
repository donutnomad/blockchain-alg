package utils

import (
	"encoding/hex"
	"github.com/samber/lo"
)

func MustDecodeHex(sHex string) []byte {
	return lo.Must1(hex.DecodeString(sHex))
}
