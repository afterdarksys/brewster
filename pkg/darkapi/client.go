// Package darkapi provides a client for interacting with the DarkAPI CVE findings API
package darkapi

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"time"
)

// Client represents a DarkAPI client
type Client struct {
	BaseURL    string
	APIKey     string
	HTTPClient *http.Client
	UserAgent  string
}

// CVEFinding represents a local CVE finding to submit to DarkAPI
type CVEFinding struct {
	CVEID              string                 `json:"cve_id"`
	Hostname           string                 `json:"hostname"`
	SystemID           string                 `json:"system_id,omitempty"`
	Platform           string                 `json:"platform,omitempty"`
	Architecture       string                 `json:"architecture,omitempty"`
	PackageName        string                 `json:"package_name"`
	PackageVersion     string                 `json:"package_version"`
	PackageManager     string                 `json:"package_manager,omitempty"`
	Ecosystem          string                 `json:"ecosystem,omitempty"`
	Severity           string                 `json:"severity"`
	CVSSScore          float64                `json:"cvss_score,omitempty"`
	Title              string                 `json:"title,omitempty"`
	Description        string                 `json:"description,omitempty"`
	DetectedBy         string                 `json:"detected_by"`
	SourceToolVersion  string                 `json:"source_tool_version,omitempty"`
	FixedInVersion     string                 `json:"fixed_in_version,omitempty"`
	RemediationText    string                 `json:"remediation_text,omitempty"`
	ReferenceURL       string                 `json:"reference_url,omitempty"`
	CWEIDs             []string               `json:"cwe_ids,omitempty"`
	RawData            map[string]interface{} `json:"raw_data,omitempty"`
	Tags               []string               `json:"tags,omitempty"`
	Notes              string                 `json:"notes,omitempty"`
}

// FindingsBatchRequest represents a batch submission request
type FindingsBatchRequest struct {
	Findings []CVEFinding           `json:"findings"`
	BatchID  string                 `json:"batch_id,omitempty"`
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// FindingsResponse represents the API response from submitting findings
type FindingsResponse struct {
	Success          bool              `json:"success"`
	Inserted         int               `json:"inserted"`
	Updated          int               `json:"updated"`
	TotalProcessed   int               `json:"total_processed"`
	TotalSubmitted   int               `json:"total_submitted"`
	SeverityBreakdown map[string]int   `json:"severity_breakdown"`
	BatchID          string            `json:"batch_id,omitempty"`
	BatchRecordID    int               `json:"batch_record_id,omitempty"`
	Errors           []SubmissionError `json:"errors,omitempty"`
	PartialSuccess   bool              `json:"partial_success,omitempty"`
}

// SubmissionError represents an error during submission
type SubmissionError struct {
	Index   int         `json:"index"`
	Error   string      `json:"error"`
	Finding CVEFinding  `json:"finding"`
}

// NewClient creates a new DarkAPI client
func NewClient(baseURL, apiKey string) *Client {
	if baseURL == "" {
		baseURL = os.Getenv("DARKAPI_URL")
		if baseURL == "" {
			baseURL = "http://localhost:8000"
		}
	}

	if apiKey == "" {
		apiKey = os.Getenv("DARKAPI_KEY")
	}

	return &Client{
		BaseURL: baseURL,
		APIKey:  apiKey,
		HTTPClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		UserAgent: "brewster/1.0",
	}
}

// SubmitFinding submits a single CVE finding to DarkAPI
func (c *Client) SubmitFinding(finding CVEFinding) (*FindingsResponse, error) {
	return c.SubmitFindings([]CVEFinding{finding}, "")
}

// SubmitFindings submits multiple CVE findings to DarkAPI
func (c *Client) SubmitFindings(findings []CVEFinding, batchID string) (*FindingsResponse, error) {
	if len(findings) == 0 {
		return nil, fmt.Errorf("no findings to submit")
	}

	// Prepare request body
	reqBody := FindingsBatchRequest{
		Findings: findings,
		BatchID:  batchID,
		Metadata: map[string]interface{}{
			"submitted_at": time.Now().Format(time.RFC3339),
			"tool":         "brewster",
			"version":      "1.0.0",
		},
	}

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	// Create HTTP request
	url := fmt.Sprintf("%s/v1/cve/findings", c.BaseURL)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", c.UserAgent)

	if c.APIKey != "" {
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.APIKey))
	}

	// Send request
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	// Read response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	// Check status code
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("API error (status %d): %s", resp.StatusCode, string(body))
	}

	// Parse response
	var findingsResp FindingsResponse
	if err := json.Unmarshal(body, &findingsResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &findingsResp, nil
}

// GetFindings retrieves CVE findings from DarkAPI with optional filters
func (c *Client) GetFindings(filters map[string]string) ([]CVEFinding, error) {
	url := fmt.Sprintf("%s/v1/cve/findings", c.BaseURL)

	// Create HTTP request
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Add query parameters
	q := req.URL.Query()
	for key, value := range filters {
		q.Add(key, value)
	}
	req.URL.RawQuery = q.Encode()

	// Set headers
	req.Header.Set("User-Agent", c.UserAgent)
	if c.APIKey != "" {
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.APIKey))
	}

	// Send request
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	// Read response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	// Check status code
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API error (status %d): %s", resp.StatusCode, string(body))
	}

	// Parse response
	var result struct {
		Success  bool         `json:"success"`
		Findings []CVEFinding `json:"findings"`
		Total    int          `json:"total"`
		Count    int          `json:"count"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return result.Findings, nil
}

// GetFindingsSummary retrieves summary statistics for CVE findings
func (c *Client) GetFindingsSummary(hostname string) (map[string]interface{}, error) {
	url := fmt.Sprintf("%s/v1/cve/findings/summary", c.BaseURL)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	if hostname != "" {
		q := req.URL.Query()
		q.Add("hostname", hostname)
		req.URL.RawQuery = q.Encode()
	}

	req.Header.Set("User-Agent", c.UserAgent)
	if c.APIKey != "" {
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.APIKey))
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API error (status %d): %s", resp.StatusCode, string(body))
	}

	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return result, nil
}

// Helper function to get current hostname
func GetHostname() string {
	hostname, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return hostname
}

// Helper function to get system information
func GetSystemInfo() (platform, arch, systemID string) {
	platform = runtime.GOOS
	arch = runtime.GOARCH

	// Try to get a system ID (MAC address hash or similar)
	// This is a simplified version - you might want to implement something more robust
	hostname, _ := os.Hostname()
	systemID = fmt.Sprintf("%s-%s-%s", hostname, platform, arch)

	return platform, arch, systemID
}

// ConvertToFinding creates a CVEFinding from audit data
func ConvertToFinding(cveID, packageName, packageVersion, ecosystem, severity string, cvssScore float64) CVEFinding {
	hostname := GetHostname()
	platform, arch, systemID := GetSystemInfo()

	return CVEFinding{
		CVEID:             cveID,
		Hostname:          hostname,
		SystemID:          systemID,
		Platform:          platform,
		Architecture:      arch,
		PackageName:       packageName,
		PackageVersion:    packageVersion,
		Ecosystem:         ecosystem,
		Severity:          severity,
		CVSSScore:         cvssScore,
		DetectedBy:        "brewster",
		SourceToolVersion: "1.0.0",
	}
}
