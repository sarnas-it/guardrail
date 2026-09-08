package engine

import (
	"crypto/sha256"
	"encoding/hex"
)

// Fingerprint — sha256(ruleID + "\x00" + file + "\x00" + value) в hex.
func Fingerprint(ruleID, file, value string) string {
	h := sha256.New()
	h.Write([]byte(ruleID))
	h.Write([]byte{0})
	h.Write([]byte(file))
	h.Write([]byte{0})
	h.Write([]byte(value))
	return hex.EncodeToString(h.Sum(nil))
}
