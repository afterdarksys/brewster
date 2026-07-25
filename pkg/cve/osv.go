package cve

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

const defaultOSVEndpoint = "https://api.osv.dev/v1/query"

// OSVSource queries OSV.dev.
type OSVSource struct {
	Client   *http.Client
	Endpoint string
}

// NewOSVSource returns an OSVSource with sane defaults.
func NewOSVSource() *OSVSource {
	return &OSVSource{
		Client:   &http.Client{Timeout: 15 * time.Second},
		Endpoint: defaultOSVEndpoint,
	}
}

func (s *OSVSource) Name() string { return "osv" }

// osvRequest is marshaled with encoding/json — never string-interpolated — so
// a name or version containing a quote/backslash cannot corrupt the payload.
type osvRequest struct {
	Package struct {
		Name      string `json:"name"`
		Ecosystem string `json:"ecosystem"`
	} `json:"package"`
	Version string `json:"version"`
}

type osvResponse struct {
	Vulns []struct {
		ID       string `json:"id"`
		Summary  string `json:"summary"`
		Details  string `json:"details"`
		Severity []struct {
			Type  string `json:"type"`
			Score string `json:"score"`
		} `json:"severity"`
		Affected []struct {
			Ranges []struct {
				Events []struct {
					Fixed string `json:"fixed"`
				} `json:"events"`
			} `json:"ranges"`
		} `json:"affected"`
		References []struct {
			Type string `json:"type"`
			URL  string `json:"url"`
		} `json:"references"`
		DatabaseSpecific struct {
			Severity string `json:"severity"`
		} `json:"database_specific"`
	} `json:"vulns"`
}

// Query resolves vulns for p across its OSV coordinates. Any transport, HTTP,
// or decode failure returns an error (never an empty "looks clean" slice).
func (s *OSVSource) Query(ctx context.Context, p Package) ([]Vuln, error) {
	coords := osvCoordinates(p)
	if len(coords) == 0 {
		return nil, nil // no confident OSV coordinate; not an error
	}
	version := normalizeVersion(p.Version)

	var out []Vuln
	for _, c := range coords {
		vulns, err := s.queryOne(ctx, c, version, p)
		if err != nil {
			return out, err
		}
		out = append(out, vulns...)
	}
	return out, nil
}

func (s *OSVSource) queryOne(ctx context.Context, c osvCoord, version string, p Package) ([]Vuln, error) {
	var reqBody osvRequest
	reqBody.Package.Name = c.Name
	reqBody.Package.Ecosystem = c.Ecosystem
	reqBody.Version = version

	buf, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("marshal osv request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.Endpoint, bytes.NewReader(buf))
	if err != nil {
		return nil, fmt.Errorf("build osv request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("osv query %s/%s: %w", c.Ecosystem, c.Name, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("osv query %s/%s: unexpected status %d", c.Ecosystem, c.Name, resp.StatusCode)
	}

	var r osvResponse
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return nil, fmt.Errorf("osv decode %s/%s: %w", c.Ecosystem, c.Name, err)
	}

	var out []Vuln
	for _, v := range r.Vulns {
		summary := v.Summary
		if summary == "" {
			summary = v.Details
		}
		out = append(out, Vuln{
			ID:        v.ID,
			Summary:   summary,
			Severity:  osvSeverity(v.Severity, v.DatabaseSpecific.Severity),
			Reference: osvReference(v.References),
			FixedIn:   osvFixedIn(v.Affected),
			Source:    "osv",
			Package:   p.Name,
			Version:   p.Version,
		})
	}
	return out, nil
}

func osvSeverity(severities []struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}, dbSpecific string) Severity {
	for _, sv := range severities {
		if s := severityFromCVSS(sv.Score); s != SeverityUnknown {
			return s
		}
	}
	if s := severityFromLabel(dbSpecific); s != SeverityUnknown {
		return s
	}
	return SeverityUnknown
}

func osvReference(refs []struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}) string {
	ref := ""
	for _, r := range refs {
		if r.Type == "ADVISORY" {
			return r.URL
		}
		if ref == "" {
			ref = r.URL
		}
	}
	return ref
}

func osvFixedIn(affected []struct {
	Ranges []struct {
		Events []struct {
			Fixed string `json:"fixed"`
		} `json:"events"`
	} `json:"ranges"`
}) string {
	for _, a := range affected {
		for _, rng := range a.Ranges {
			for _, e := range rng.Events {
				if e.Fixed != "" {
					return e.Fixed
				}
			}
		}
	}
	return ""
}
