package common

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"sync"
	"time"
)

var (
	hashes sync.Map

	// B64StdWithPadding is a base64 encoding with standard padding.
	B64StdWithPadding = base64.StdEncoding.WithPadding(base64.StdPadding)

	// B64URLWithPadding is a base64 URL safe encoding without padding.
	B64URLNoPadding = base64.URLEncoding.WithPadding(base64.NoPadding)

	// B32StdNoPadding is a base32 encoding without padding.
	B32StdNoPadding = base32.StdEncoding.WithPadding(base32.NoPadding)
)

// DecodeFromQuery decodes a URL query parameter into a map.
// It uses the HMAC to verify the integrity of the data.
func DecodeFromQuery(in string) (map[string]any, error) {
	if len(in) == 0 {
		return nil, fmt.Errorf("empty input")
	}

	enc, err := url.QueryUnescape(in)
	if err != nil {
		return nil, err
	}

	data, ok := hashes.LoadAndDelete(enc)
	if !ok {
		return nil, fmt.Errorf("hash not found")
	}

	out, ok := data.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("invalid data type")
	}

	return out, nil
}

// EncodeForQuery encodes the input map into a URL query parameter.
// It uses JSON encoding and base64 URL safe encoding without padding.
// It also calculates the HMAC of the JSON data using the provided secret.
func EncodeForQuery(in map[string]any, secret []byte) (string, error) {
	if len(in) == 0 {
		return "", fmt.Errorf("empty input")
	}

	if len(secret) == 0 {
		return "", fmt.Errorf("empty secret")
	}

	data, err := json.Marshal(in)
	if err != nil {
		return "", err
	}

	h := hmac.New(sha256.New, secret)
	if _, err := h.Write(data); err != nil {
		return "", err
	}

	sum := B64URLNoPadding.EncodeToString(h.Sum(nil))
	hashes.Store(sum, in)

	return url.QueryEscape(sum), nil
}

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
