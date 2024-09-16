package tool

import (
	"encoding/hex"
	"golang.org/x/crypto/sha3"
)

func Sha3Hash256(data []byte) string {
	hash := sha3.Sum256(data)
	return hex.EncodeToString(hash[:])
}

func Sha3256Hash(data ...[]byte) string {
	h := sha3.New256()
	for _, d := range data {
		h.Write(d)
	}
	return hex.EncodeToString(h.Sum(nil))
}
