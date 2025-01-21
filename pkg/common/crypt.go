package common

import (
	"crypto/rand"
	"encoding/base32"
	"encoding/base64"
	"fmt"
	"time"
)

var (
	// B64StdWithPadding is a base64 encoding with standard padding.
	B64StdWithPadding = base64.StdEncoding.WithPadding(base64.StdPadding)

	// B64URLWithPadding is a base64 URL safe encoding without padding.
	B64URLNoPadding = base64.URLEncoding.WithPadding(base64.NoPadding)

	// B32StdNoPadding is a base32 encoding without padding.
	B32StdNoPadding = base32.StdEncoding.WithPadding(base32.NoPadding)
)

// GetNonce generates a random nonce.
// It returns a base64 encoded string.
// If the random number generator fails, it uses the current time for randomness.
func GetNonce() (string, error) {
	nonce := make([]byte, 32)
	_, err := rand.Read(nonce)
	if err != nil {
		nonce = []byte(fmt.Sprint(time.Now().Unix() + int64(time.Now().Nanosecond())))
	}

	return B64StdWithPadding.EncodeToString(nonce), err
}

// MakeKeyPair generates a pair of 32-byte keys.
// If the input is empty, it generates a random key.
// If the input is 64 bytes, it splits it into two keys.
// If the input is less than 64 bytes, it fills just the first key and leaves the second key empty.
func MakeKeyPair(in []byte) ([]byte, []byte) {
	key1 := make([]byte, 32)
	key2 := make([]byte, 32)

	if len(in) >= 64 {
		copy(key1, in[:32])
		copy(key2, in[32:])

	} else if len(in) > 0 {
		copy(key1, in)

	} else {
		_, _ = rand.Read(key1)
		_, _ = rand.Read(key2)

	}

	return key1, key2
}
