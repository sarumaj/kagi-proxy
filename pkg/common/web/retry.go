package web

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"time"

	"github.com/sarumaj/kagi-proxy/pkg/common"
	"go.uber.org/zap"
)

type (
	// RetryConfig is the configuration for the RetryTransport.
	RetryConfig struct {
		MaxRetries int           `json:"max_retries,omitempty"`
		RetryCodes []int         `json:"retry_codes,omitempty"`
		RetryDelay time.Duration `json:"-"`
	}

	// RetryTransport is a custom transport that retries requests on failure.
	RetryTransport struct {
		Config RetryConfig
		http.RoundTripper
	}
)

// MarshalJSON implements the json.Marshaler interface for RetryConfig.
func (r RetryConfig) MarshalJSON() ([]byte, error) {
	type Alias RetryConfig
	return json.Marshal(&struct {
		RetryDelay int64 `json:"retry_delay,omitempty"`
		*Alias
	}{
		RetryDelay: int64(r.RetryDelay / time.Millisecond),
		Alias:      (*Alias)(&r),
	})
}

// RoundTrip implements the http.RoundTripper interface for RetryTransport.
func (t *RetryTransport) RoundTrip(req *http.Request) (response *http.Response, err error) {
	// Create a new request body reader for each attempt
	var buffer []byte
	if req.Body != nil {
		buffer, err = io.ReadAll(req.Body)
		if err != nil {
			return nil, err
		}
		_ = req.Body.Close()
	}

	for attempt := 0; attempt <= t.Config.MaxRetries; attempt++ {
		// Reset request body for each attempt
		if len(buffer) > 0 {
			req.Body = io.NopCloser(bytes.NewBuffer(buffer))
		}

		response, err = t.RoundTripper.RoundTrip(req)
		if err != nil {
			common.Logger().Warn("Network error, retrying request",
				zap.String("url", req.URL.String()),
				zap.Int("attempt", attempt),
				zap.Error(err))

			time.Sleep(t.Config.RetryDelay * time.Duration(attempt+1))
			continue
		}

		isRetryable := false
		for _, code := range t.Config.RetryCodes {
			if response.StatusCode == code {
				isRetryable = true
				break
			}
		}

		if isRetryable {
			common.Logger().Warn("Retryable status code, retrying request",
				zap.String("url", req.URL.String()),
				zap.Int("attempt", attempt),
				zap.Int("status", response.StatusCode))

			_ = response.Body.Close()
			time.Sleep(t.Config.RetryDelay * time.Duration(attempt+1))
			continue
		}

		return
	}

	return
}
