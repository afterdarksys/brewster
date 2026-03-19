package config

// AuditConfig holds configuration for local audits
type AuditConfig struct {
	CheckCVE         bool
	CheckAbandoned   bool
	CheckHTTP        bool
	Verbose          bool

	// DarkAPI integration
	SubmitToDarkAPI  bool
	DarkAPIURL       string
	DarkAPIKey       string
}
