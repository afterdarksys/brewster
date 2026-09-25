package cve

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

const defaultOSVEndpoint = "https://api.osv.dev/v1/query"

// OSVSource queries OSV.dev.
type OSVSource struct {
	Client   *http.Client
	Endpoint string
	MaxBytes int64
}

// NewOSVSource returns an OSVSource with sane defaults.
func NewOSVSource() *OSVSource {
	return &OSVSource{
		Client:   newHTTPClient(15 * time.Second),
		Endpoint: defaultOSVEndpoint,
	}
}

func (s *OSVSource) Name() string { return "osv" }

type osvRequest struct {
	Package struct {
		Name      string `json:"name"`
		Ecosystem string `json:"ecosystem"`
	} `json:"package"`
	Version string `json:"version"`
}

type osvAffected struct {
	Package struct {
		Name      string `json:"name"`
		Ecosystem string `json:"ecosystem"`
	} `json:"package"`
	Ranges []struct {
		Events []struct {
			Introduced   string `json:"introduced"`
			Fixed        string `json:"fixed"`
			LastAffected string `json:"last_affected"`
		} `json:"events"`
	} `json:"ranges"`
}

type osvResponse struct {
	Vulns []struct {
		ID       string   `json:"id"`
		Aliases  []string `json:"aliases"`
		Summary  string   `json:"summary"`
		Details  string   `json:"details"`
		Severity []struct {
			Type  string `json:"type"`
			Score string `json:"score"`
		} `json:"severity"`
		Affected   []osvAffected `json:"affected"`
		References []struct {
			Type string `json:"type"`
			URL  string `json:"url"`
		} `json:"references"`
		DatabaseSpecific struct {
			Severity string `json:"severity"`
		} `json:"database_specific"`
	} `json:"vulns"`
}

func (s *OSVSource) Query(ctx context.Context, p Package) ([]Vuln, error) {
	coords := osvCoordinates(p)
	if len(coords) == 0 {
		return nil, nil
	}
	version := normalizeVersion(p.Version)
	if version == "" {
		return nil, fmt.Errorf("osv: missing version for %s", p.Name)
	}

	var out []Vuln
	var errs []error
	for _, c := range coords {
		vulns, err := s.queryOne(ctx, c, version, p)
		out = append(out, vulns...)
		if err != nil {
			errs = append(errs, err)
		}
	}
	return out, errors.Join(errs...)
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

	body, err := readLimited(resp.Body, bodyLimit(s.MaxBytes))
	if err != nil {
		return nil, fmt.Errorf("osv read %s/%s: %w", c.Ecosystem, c.Name, err)
	}
	var r osvResponse
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, fmt.Errorf("osv decode %s/%s: %w", c.Ecosystem, c.Name, err)
	}

	var out []Vuln
	for _, v := range r.Vulns {
		summary := v.Summary
		if summary == "" {
			summary = v.Details
		}
		id, aliases := preferCVE(v.ID, v.Aliases)
		out = append(out, Vuln{
			ID:        id,
			Aliases:   aliases,
			Summary:   summary,
			Severity:  osvSeverity(v.Severity, v.DatabaseSpecific.Severity),
			Reference: osvReference(v.References),
			FixedIn:   osvFixedIn(v.Affected, c, version),
			Source:    "osv",
			Package:   p.Name,
			Version:   p.Version,
		})
	}
	return out, nil
}

func preferCVE(id string, aliases []string) (string, []string) {
	ids := make([]string, 0, 1+len(aliases))
	if id != "" {
		ids = append(ids, id)
	}
	ids = append(ids, aliases...)

	chosen := id
	for _, candidate := range ids {
		if strings.HasPrefix(candidate, "CVE-") {
			chosen = candidate
			break
		}
	}
	var rest []string
	seen := map[string]bool{chosen: true}
	for _, candidate := range ids {
		if candidate == "" || seen[candidate] {
			continue
		}
		seen[candidate] = true
		rest = append(rest, candidate)
	}
	return chosen, rest
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

func osvFixedIn(affected []osvAffected, c osvCoord, installed string) string {
	var candidates []string
	for _, a := range affected {
		if a.Package.Name != "" && a.Package.Name != c.Name {
			continue
		}
		if a.Package.Ecosystem != "" && a.Package.Ecosystem != c.Ecosystem {
			continue
		}
		for _, rng := range a.Ranges {
			inRange := true
			for _, e := range rng.Events {
				switch {
				case e.Introduced != "":
					less, ok := versionLess(installed, e.Introduced)
					inRange = ok && !less
				case e.Fixed != "":
					if less, ok := versionLess(installed, e.Fixed); inRange && ok && less {
						candidates = append(candidates, e.Fixed)
					}
					inRange = false
				case e.LastAffected != "":
					inRange = false
				}
			}
		}
	}
	if len(candidates) == 0 {
		return ""
	}
	best := candidates[0]
	for _, candidate := range candidates[1:] {
		if less, ok := versionLess(candidate, best); ok && less {
			best = candidate
		}
	}
	return best
}
