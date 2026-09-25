package cve

import (
	"errors"
	"io"
	"net/http"
	"time"
)

var errResponseTooLarge = errors.New("response exceeds size limit")

const maxResponseBytes = 8 << 20

// newHTTPClient refuses redirects so the NVD API key header stays on nvd.nist.gov.
func newHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func bodyLimit(n int64) int64 {
	if n > 0 {
		return n
	}
	return maxResponseBytes
}

func readLimited(r io.Reader, limit int64) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > limit {
		return nil, errResponseTooLarge
	}
	return body, nil
}
