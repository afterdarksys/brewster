# CVE Reporting Integration

Brewster can now automatically report discovered CVE findings to DarkAPI for centralized vulnerability management and tracking.

## Overview

When Brewster scans your Homebrew installation for vulnerabilities, it can automatically submit any CVE findings to DarkAPI, where they are:
- Stored in a centralized database
- Tracked across multiple systems
- Analyzed for trends and severity
- Available for reporting and dashboards

## Architecture

### Components

1. **Brewster (Client)**
   - Scans local Homebrew packages for CVEs using OSV.dev
   - Converts findings to DarkAPI format
   - Submits findings via REST API
   - Located: `pkg/darkapi/client.go`

2. **DarkAPI (Server)**
   - Receives CVE findings via REST endpoints
   - Stores findings in PostgreSQL database
   - Provides query and analytics endpoints
   - Located: `darkapi.io/api/cve_routes.py`

3. **Database**
   - Tables: `cve_local_findings`, `monitored_systems`, `cve_finding_batches`
   - Views for analytics and reporting
   - Migration: `darkapi.io/migrations/008_cve_local_findings.sql`

## Configuration

### Environment Variables

```bash
# DarkAPI URL (required)
export DARKAPI_URL="https://darkapi.yourdomain.com"

# DarkAPI API Key (required)
export DARKAPI_KEY="your-api-key-here"
```

### Command Line Flags

```bash
# Submit CVE findings during audit
brewster audit --submit

# Specify DarkAPI URL and key via flags
brewster audit --submit \
  --darkapi-url="https://darkapi.yourdomain.com" \
  --darkapi-key="your-key"

# Full comprehensive scan with submission
brewster scan --submit
```

## Usage Examples

### Basic Audit with CVE Submission

```bash
# Set environment variables
export DARKAPI_URL="http://localhost:8000"
export DARKAPI_KEY="your-api-key"

# Run audit with submission
brewster audit --submit --verbose
```

Output:
```
🍺 Brewster Security Audit
==========================
  Scanning 150 packages and 5 taps...
  Found 3 CVE vulnerabilities
  Submitting 3 CVE findings to DarkAPI...
  DarkAPI submission: 3 inserted, 0 updated
  Successfully submitted CVE findings to DarkAPI

Summary:
  Critical: 1
  High: 2
  Medium: 0
  Low: 0
```

### Comprehensive Scan with Submission

```bash
brewster scan --submit --verbose
```

This will:
1. Audit local installation
2. Submit CVE findings to DarkAPI
3. Vet installed taps
4. Check ecosystem intelligence
5. Generate combined report

## API Endpoints

### DarkAPI Endpoints

#### Submit CVE Findings
```
POST /v1/cve/findings
Content-Type: application/json
Authorization: Bearer YOUR_API_KEY

{
  "findings": [
    {
      "cve_id": "CVE-2024-12345",
      "hostname": "macbook-pro.local",
      "package_name": "openssl",
      "package_version": "1.1.1k",
      "severity": "HIGH",
      "cvss_score": 7.5,
      "detected_by": "brewster",
      ...
    }
  ],
  "batch_id": "brewster-macbook-1234567890"
}
```

#### Retrieve Findings
```
GET /v1/cve/findings?hostname=macbook-pro&severity=HIGH,CRITICAL
```

#### Get Summary Statistics
```
GET /v1/cve/findings/summary?hostname=macbook-pro
```

#### Update Finding Status
```
PATCH /v1/cve/findings/123
{
  "status": "patched",
  "acknowledged_by": "admin",
  "notes": "Updated to patched version"
}
```

## Data Model

### CVE Finding Structure

```go
type CVEFinding struct {
    CVEID              string                 // CVE-2024-12345
    Hostname           string                 // macbook-pro.local
    SystemID           string                 // unique system identifier
    Platform           string                 // darwin, linux, windows
    Architecture       string                 // arm64, x86_64
    PackageName        string                 // openssl
    PackageVersion     string                 // 1.1.1k
    PackageManager     string                 // homebrew
    Ecosystem          string                 // Homebrew
    Severity           string                 // CRITICAL, HIGH, MEDIUM, LOW
    CVSSScore          float64                // 7.5
    Title              string                 // Vulnerability title
    Description        string                 // Full description
    DetectedBy         string                 // brewster
    SourceToolVersion  string                 // 1.0.0
    FixedInVersion     string                 // 1.1.1m
    RemediationText    string                 // How to fix
    ReferenceURL       string                 // https://nvd.nist.gov/...
    CWEIDs             []string               // [CWE-119, CWE-120]
    RawData            map[string]interface{} // Full finding data
}
```

### Database Schema

**cve_local_findings** - Main findings table
- CVE information (ID, severity, CVSS score)
- System information (hostname, platform, architecture)
- Package information (name, version, ecosystem)
- Detection information (detected_by, detected_at)
- Remediation information (fixed_in_version, patched)
- Status tracking (open, acknowledged, patched, false_positive)

**monitored_systems** - System inventory
- Tracks all systems reporting findings
- Last seen timestamps
- Agent information

**cve_finding_batches** - Batch submission tracking
- Groups findings by submission
- Severity counts per batch

## Analytics Views

DarkAPI provides several pre-built views for analytics:

- `active_vulnerabilities_by_severity` - Count of active vulnerabilities by severity
- `vulnerable_hosts_summary` - Summary of vulnerabilities per host
- `top_cves_by_prevalence` - Most common CVEs across systems
- `vulnerable_packages_summary` - Most vulnerable packages
- `recent_cve_discoveries` - Findings from last 7 days
- `system_health_scores` - Health scores for monitored systems

## Security Considerations

### API Authentication

- Use strong API keys (minimum 32 characters)
- Store API keys in environment variables, not in code
- Rotate API keys regularly
- Use HTTPS in production

### Data Privacy

- CVE findings include system information (hostname, platform)
- Ensure your DarkAPI instance is properly secured
- Consider masking sensitive hostnames if needed
- Use network isolation for DarkAPI deployment

### Error Handling

- Audit continues even if submission fails
- Submission errors are logged but don't fail the audit
- Partial success is supported (some findings submitted, some failed)

## Troubleshooting

### Connection Issues

```bash
# Test DarkAPI connectivity
curl -H "Authorization: Bearer YOUR_KEY" \
  http://localhost:8000/v1/cve/findings/summary

# Check environment variables
echo $DARKAPI_URL
echo $DARKAPI_KEY
```

### Submission Failures

Check verbose output:
```bash
brewster audit --submit --verbose
```

Common issues:
- Missing or invalid API key
- DarkAPI server not running
- Network connectivity issues
- Database migration not applied

### Database Setup

Ensure the migration has been applied:
```bash
cd darkapi.io
psql -U darkapi -d darkapi -f migrations/008_cve_local_findings.sql
```

## Development

### Testing the Integration

1. **Start DarkAPI locally:**
   ```bash
   cd darkapi.io
   python -m flask run --port 8000
   ```

2. **Run Brewster audit with submission:**
   ```bash
   export DARKAPI_URL="http://localhost:8000"
   export DARKAPI_KEY="test-key"
   brewster audit --submit --verbose
   ```

3. **Query findings:**
   ```bash
   curl -H "Authorization: Bearer test-key" \
     "http://localhost:8000/v1/cve/findings?hostname=$(hostname)"
   ```

### Adding Custom Fields

To add custom fields to findings:

1. Update database migration (`008_cve_local_findings.sql`)
2. Update API endpoint (`api/cve_routes.py`)
3. Update Go client struct (`pkg/darkapi/client.go`)
4. Update submission function (`pkg/audit/audit.go`)

## Roadmap

Future enhancements:
- [ ] Real-time CVE alerting via webhooks
- [ ] Integration with Slack/email notifications
- [ ] Automated remediation suggestions
- [ ] CVE trend analysis and reporting
- [ ] Integration with CI/CD pipelines
- [ ] Support for other package managers (pip, npm, etc.)
- [ ] Dashboard UI for vulnerability management
- [ ] Export to SARIF format

## Support

For issues or questions:
- GitHub Issues: https://github.com/afterdarksys/brewster/issues
- Documentation: https://docs.afterdarktech.com/brewster
- Email: support@afterdarktech.com
