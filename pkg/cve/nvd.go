package cve

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	defaultNVDEndpoint = "https://services.nvd.nist.gov/rest/json/cves/2.0"
	nvdPageSize        = 2000
	nvdMaxPages        = 25
)

// NVDSource queries the NVD CVE API with a curated versioned CPE.
type NVDSource struct {
	Client      *http.Client
	Endpoint    string
	APIKey      string
	MinInterval time.Duration
	MaxBytes    int64

	mu   sync.Mutex
	last time.Time
}

func NewNVDSource(apiKey string) *NVDSource {
	interval := 6 * time.Second
	if strings.TrimSpace(apiKey) != "" {
		interval = 700 * time.Millisecond
	}
	return &NVDSource{
		Client:      newHTTPClient(20 * time.Second),
		Endpoint:    defaultNVDEndpoint,
		APIKey:      strings.TrimSpace(apiKey),
		MinInterval: interval,
	}
}

func (s *NVDSource) Name() string { return "nvd" }

func (s *NVDSource) throttle(ctx context.Context) error {
	s.mu.Lock()
	wait := time.Until(s.last.Add(s.MinInterval))
	if wait < 0 {
		wait = 0
	}
	s.last = time.Now().Add(wait)
	s.mu.Unlock()
	if wait == 0 {
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
	TotalResults    int `json:"totalResults"`
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

func (s *NVDSource) Query(ctx context.Context, p Package) ([]Vuln, error) {
	coords := curatedCPE[normalizeName(p.Name)]
	if len(coords) == 0 {
		return nil, nil
	}
	version := normalizeVersion(p.Version)
	if version == "" {
		return nil, fmt.Errorf("nvd: missing version for %s", p.Name)
	}

	var out []Vuln
	var errs []error
	seen := map[string]bool{}
	for _, c := range coords {
		vulns, err := s.queryCPE(ctx, p, c, version)
		for _, v := range vulns {
			if seen[v.ID] {
				continue
			}
			seen[v.ID] = true
			out = append(out, v)
		}
		if err != nil {
			errs = append(errs, err)
		}
	}
	return out, errors.Join(errs...)
}

func (s *NVDSource) queryCPE(ctx context.Context, p Package, c cpeCoord, version string) ([]Vuln, error) {
	cpe := fmt.Sprintf("cpe:2.3:a:%s:%s:%s:*:*:*:*:*:*:*",
		escapeCPE(c.Vendor), escapeCPE(c.Product), escapeCPE(version))

	var out []Vuln
	start := 0
	total := -1
	for page := 0; page < nvdMaxPages; page++ {
		vulns, resp, err := s.queryPage(ctx, p, cpe, start)
		if err != nil {
			return out, err
		}
		if total == -1 {
			total = resp.TotalResults
		}
		out = append(out, vulns...)
		if len(out) >= total || total == 0 {
			return out, nil
		}
		if len(resp.Vulnerabilities) == 0 {
			return out, fmt.Errorf("nvd pagination stalled for %s at %d/%d", p.Name, len(out), total)
		}
		start += len(resp.Vulnerabilities)
	}
	return out, fmt.Errorf("nvd result cap for %s: %d of %d", p.Name, len(out), total)
}

func (s *NVDSource) queryPage(ctx context.Context, p Package, cpe string, start int) ([]Vuln, nvdResponse, error) {
	q := url.Values{}
	q.Set("virtualMatchString", cpe)
	q.Set("resultsPerPage", strconv.Itoa(nvdPageSize))
	q.Set("startIndex", strconv.Itoa(start))
	reqURL := s.Endpoint + "?" + q.Encode()

	if err := s.throttle(ctx); err != nil {
		return nil, nvdResponse{}, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, nvdResponse{}, fmt.Errorf("build nvd request: %w", err)
	}
	if s.APIKey != "" {
		req.Header.Set("apiKey", s.APIKey)
	}

	resp, err := s.Client.Do(req)
	if err != nil {
		return nil, nvdResponse{}, fmt.Errorf("nvd query %s: %w", p.Name, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, nvdResponse{}, fmt.Errorf("nvd query %s: unexpected status %d", p.Name, resp.StatusCode)
	}

	body, err := readLimited(resp.Body, bodyLimit(s.MaxBytes))
	if err != nil {
		return nil, nvdResponse{}, fmt.Errorf("nvd read %s: %w", p.Name, err)
	}
	var r nvdResponse
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, nvdResponse{}, fmt.Errorf("nvd decode %s: %w", p.Name, err)
	}

	var out []Vuln
	for _, item := range r.Vulnerabilities {
		cve := item.CVE
		out = append(out, Vuln{
			ID:        cve.ID,
			Summary:   nvdDescription(cve.Descriptions),
			Severity:  nvdSeverity(cve.Metrics.CvssMetricV31, cve.Metrics.CvssMetricV30, cve.Metrics.CvssMetricV40),
			Reference: nvdReference(cve.References),
			Source:    "nvd",
			Package:   p.Name,
			Version:   p.Version,
		})
	}
	return out, r, nil
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
