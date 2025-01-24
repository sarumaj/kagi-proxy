package common

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"time"

	"github.com/gin-contrib/sessions"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

var (
	// B64StdWithPadding is a base64 encoding with standard padding.
	B64StdWithPadding = base64.StdEncoding.WithPadding(base64.StdPadding)

	// B64URLWithPadding is a base64 URL safe encoding without padding.
	B64URLNoPadding = base64.URLEncoding.WithPadding(base64.NoPadding)

	// B32StdNoPadding is a base32 encoding without padding.
	B32StdNoPadding = base32.StdEncoding.WithPadding(base32.NoPadding)
)

// CTEqual is a constant-time comparison function.
func CTEqual[S interface{ ~string | ~[]byte }](a, b S) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// DecodeFromQuery decodes a URL query parameter into a map.
// It uses the HMAC checksum stored in the session to verify the integrity of the data.
// The session has to be saved after calling this function.
func DecodeFromQuery(in string, secret []byte, session sessions.Session) (map[string]any, error) {
	if len(in) == 0 {
		return nil, fmt.Errorf("empty input")
	}

	if len(secret) == 0 {
		return nil, fmt.Errorf("empty secret")
	}

	enc, err := url.QueryUnescape(in)
	if err != nil {
		return nil, err
	}

	data, err := B64URLNoPadding.DecodeString(enc)
	if err != nil {
		return nil, err
	}

	h := hmac.New(sha256.New, secret)
	if _, err := h.Write(data); err != nil {
		return nil, err
	}

	defer session.Delete("checksum")
	if !CTEqual(B64StdWithPadding.EncodeToString(h.Sum(nil)), QuickGet[string](session, "checksum")) {
		return nil, fmt.Errorf("checksum mismatch")
	}

	var out map[string]any
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}

	return out, nil
}

// EncodeForQuery encodes the input map into a URL query parameter.
// It uses JSON encoding and base64 URL safe encoding without padding.
// It also calculates the HMAC checksum of the JSON data using the provided secret
// and stores it in the session. Checksum is used to verify the integrity of the data.
// The session has to be saved after calling this function.
func EncodeForQuery(in map[string]any, secret []byte, session sessions.Session) (string, error) {
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

	session.Set("checksum", B64StdWithPadding.EncodeToString(h.Sum(nil)))
	return url.QueryEscape(B64URLNoPadding.EncodeToString(data)), nil
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

func NewUUID() string {
	uuid, err := uuid.NewRandom()
	if err != nil {
		Logger().Error("failed to generate UUID", zap.Error(err))
	}

	return uuid.String()
}
