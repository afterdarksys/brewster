package cve

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const defaultNVDEndpoint = "https://services.nvd.nist.gov/rest/json/cves/2.0"

// NVDSource queries the NVD 2.0 CVE API by CPE match string. Unlike the old
// keyword-substring approach (which flagged any CVE whose description merely
// mentioned the formula name, ignoring version — a false-positive firehose),
// this asks NVD to match a versioned CPE so NVD performs the affected-range
// check server-side.
type NVDSource struct {
	Client      *http.Client
	Endpoint    string
	APIKey      string
	MinInterval time.Duration

	mu   sync.Mutex
	last time.Time
}

// NewNVDSource returns an NVDSource. Without an API key NVD allows only ~5
// requests/30s, so the interval is throttled accordingly; with a key it is ~50.
func NewNVDSource(apiKey string) *NVDSource {
	interval := 6 * time.Second
	if strings.TrimSpace(apiKey) != "" {
		interval = 700 * time.Millisecond
	}
	return &NVDSource{
		Client:      &http.Client{Timeout: 20 * time.Second},
		Endpoint:    defaultNVDEndpoint,
		APIKey:      strings.TrimSpace(apiKey),
		MinInterval: interval,
	}
}

func (s *NVDSource) Name() string { return "nvd" }

// throttle blocks until MinInterval has elapsed since the previous request.
func (s *NVDSource) throttle(ctx context.Context) error {
	s.mu.Lock()
	wait := time.Until(s.last.Add(s.MinInterval))
	s.last = time.Now().Add(wait)
	s.mu.Unlock()
	if wait <= 0 {
		return nil
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

type nvdResponse struct {
	Vulnerabilities []struct {
		CVE struct {
			ID           string `json:"id"`
			Descriptions []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			} `json:"descriptions"`
			Metrics struct {
				CvssMetricV31 []nvdMetric `json:"cvssMetricV31"`
				CvssMetricV30 []nvdMetric `json:"cvssMetricV30"`
				CvssMetricV40 []nvdMetric `json:"cvssMetricV40"`
			} `json:"metrics"`
			References []struct {
				URL string `json:"url"`
			} `json:"references"`
		} `json:"cve"`
	} `json:"vulnerabilities"`
}

type nvdMetric struct {
	CvssData struct {
		BaseScore    float64 `json:"baseScore"`
		BaseSeverity string  `json:"baseSeverity"`
	} `json:"cvssData"`
}

// Query resolves vulns for p via a versioned CPE match string.
func (s *NVDSource) Query(ctx context.Context, p Package) ([]Vuln, error) {
	product := strings.ToLower(normalizeName(p.Name))
	version := normalizeVersion(p.Version)
	if product == "" || version == "" {
		return nil, nil
	}

	// cpe:2.3:a:<vendor>:<product>:<version>:... — vendor wildcarded, version
	// concrete so NVD applies affected-range matching.
	cpe := fmt.Sprintf("cpe:2.3:a:*:%s:%s:*:*:*:*:*:*:*", product, version)
	q := url.Values{}
	q.Set("virtualMatchString", cpe)
	q.Set("resultsPerPage", "50")
	reqURL := s.Endpoint + "?" + q.Encode()

	if err := s.throttle(ctx); err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("build nvd request: %w", err)
	}
	if s.APIKey != "" {
		req.Header.Set("apiKey", s.APIKey)
	}

	resp, err := s.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("nvd query %s: %w", product, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("nvd query %s: unexpected status %d", product, resp.StatusCode)
	}

	var r nvdResponse
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return nil, fmt.Errorf("nvd decode %s: %w", product, err)
	}

	var out []Vuln
	for _, item := range r.Vulnerabilities {
		c := item.CVE
		out = append(out, Vuln{
			ID:        c.ID,
			Summary:   nvdDescription(c.Descriptions),
			Severity:  nvdSeverity(c.Metrics.CvssMetricV31, c.Metrics.CvssMetricV30, c.Metrics.CvssMetricV40),
			Reference: nvdReference(c.References),
			Source:    "nvd",
			Package:   p.Name,
			Version:   p.Version,
		})
	}
	return out, nil
}

func nvdDescription(descs []struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}) string {
	for _, d := range descs {
		if d.Lang == "en" {
			return d.Value
		}
	}
	if len(descs) > 0 {
		return descs[0].Value
	}
	return ""
}

func nvdSeverity(sets ...[]nvdMetric) Severity {
	for _, set := range sets {
		for _, m := range set {
			if s := severityFromLabel(m.CvssData.BaseSeverity); s != SeverityUnknown {
				return s
			}
			if m.CvssData.BaseScore > 0 {
				return severityFromScore(m.CvssData.BaseScore)
			}
		}
	}
	return SeverityUnknown
}

func nvdReference(refs []struct {
	URL string `json:"url"`
}) string {
	if len(refs) > 0 {
		return refs[0].URL
	}
	return ""
}
