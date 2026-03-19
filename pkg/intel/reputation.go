package intel

import (
	"context"
	"net/http"
	"time"
)

// ReputationConfig holds the configuration for the Threat Intel client.
type ReputationConfig struct {
	APIEndpoint string
	APIKey      string
	Timeout     time.Duration
}

// ReputationResult represents the result of a reputation check.
type ReputationResult struct {
	Domain        string
	RiskScore     int      // 0-100, where 100 is highly malicious
	Categories    []string // e.g., "typosquatting", "malware", "newly_registered"
	IsMalicious   bool
	Recommendation string
}

// Client is the interface to the AfterDark Threat Intel Service.
type Client struct {
	config     ReputationConfig
	httpClient *http.Client
}

// NewClient creates a new Threat Intel client.
func NewClient(cfg ReputationConfig) *Client {
	if cfg.Timeout == 0 {
		cfg.Timeout = 10 * time.Second
	}
	// Default to a public mock endpoint if not provided, or a placeholder
	if cfg.APIEndpoint == "" {
		cfg.APIEndpoint = "https://api.darkapi.io/v1/intel/reputation"
	}
	return &Client{
		config: cfg,
		httpClient: &http.Client{
			Timeout: cfg.Timeout,
		},
	}
}

// CheckURL checks the reputation of a URL's domain.
func (c *Client) CheckURL(ctx context.Context, targetURL string) (*ReputationResult, error) {
	// For now, this is a mock implementation that returns some standard results.
	// In production, this would make an actual HTTP call to DarkAPI.io or DNSScience.

	// Example logic: Flag everything on "dropbox.com" or "mega.nz" as medium risk,
	// and "github-updater.com" as high risk (typosquatting).
	
	result := &ReputationResult{
		Domain:      targetURL,
		RiskScore:   0,
		IsMalicious: false,
	}

	// This is simple mocking logic for demonstration
	// In real environment, parsing the URL to get the hostname is required
	if contains(targetURL, "dropbox.com") || contains(targetURL, "mega.nz") {
		result.RiskScore = 60
		result.Categories = []string{"file_sharing", "unverified_source"}
		result.Recommendation = "Verify checksum manually, high risk of payload swapping"
	} else if contains(targetURL, "github-updater") || contains(targetURL, "githup.com") {
		result.RiskScore = 95
		result.IsMalicious = true
		result.Categories = []string{"typosquatting", "malicious"}
		result.Recommendation = "DO NOT INSTALL. High probability of supply chain attack."
	} else {
		result.RiskScore = 10
		result.Categories = []string{"benign"}
		result.Recommendation = "Safe to proceed"
	}

	// Simulate network latency
	time.Sleep(100 * time.Millisecond)

	return result, nil
}

// Helper for simple mocking
func contains(s, substr string) bool {
	return len(s) >= len(substr) && stringMatches(s, substr)
}

func stringMatches(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
