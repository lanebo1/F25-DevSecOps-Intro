# Lab 10 Submission — Vulnerability Management & Response with DefectDojo

## Task 1 — DefectDojo Local Setup

### 1.1: Clone and start DefectDojo

**Results:**

- Repository cloned successfully
- Build completed successfully
- Container status: All containers healthy and running (nginx on port 8080, postgres, redis/valkey, uwsgi, celery workers)

### 1.2: Get admin credentials

**Admin credentials obtained:**

- Username: admin
- Password: m9tLLn3ltyNxYKPUarXQKW

**Source:** Extracted from initializer container logs using `docker compose logs initializer`

## Task 2 — Import Prior Findings

### 2.1: Get API token and set variables

**API Configuration:**

- API URL: http://localhost:8080/api/v2
- API Token: 60ddae754963d6d9ede193cb1ea8fe51692f5f11

**Environment variables to set:**

```bash
export DD_API="http://localhost:8080/api/v2"
export DD_TOKEN="60ddae754963d6d9ede193cb1ea8fe51692f5f11"
export DD_PRODUCT_TYPE="Engineering"
export DD_PRODUCT="Juice Shop"
export DD_ENGAGEMENT="Labs Security Testing"
```

### 2.3: Run the importer script

**Import results:**

- **ZAP**: Skipped - file `zap-report-noauth.json` not found (used `zap-report.json` instead)
- **Semgrep**: Imported successfully - 0 findings (test_id: 1)
- **Trivy**: Imported successfully - 74 findings (9 critical, 28 high, 33 medium, 4 low) (test_id: 2)
- **Nuclei**: Imported successfully - 23 findings (21 info, 1 low, 1 medium) (test_id: 3)
- **Grype**: Imported successfully - 65 findings (8 critical, 21 high, 23 medium, 1 low, 12 info) (test_id: 4)

**Total findings imported:** 162 across 4 tools
**Import response files saved to:** `labs/lab10/imports/`

## Task 3 — Reporting & Program Metrics

### 3.1: Create a baseline progress snapshot

**Metrics snapshot created:** `labs/lab10/report/metrics-snapshot.md`

**Current findings breakdown:**

- Date captured: November 14, 2025
- Active findings by severity:
  - Critical: 17
  - High: 49
  - Medium: 57
  - Low: 6
  - Informational: 33
- Total active findings: 162
- All findings are currently active and unverified (imported with active=false, verified=false)
- No findings have been mitigated or closed yet

### 3.2: Generate governance-ready artifacts

**Generated artifacts:**

- `labs/lab10/report/dojo-report.html` - HTML engagement report with all findings
- `labs/lab10/report/findings.csv` - CSV export of all findings with key details

### 3.3: Extract key metrics

**Key metrics summary:**

- **Total findings**: 162 active findings imported from 4 security tools
- **Findings by tool**: Trivy (74 findings), Grype (65 findings), Nuclei (23 findings), Semgrep (0 findings)
- **Findings by severity**: 17 critical, 49 high, 57 medium, 6 low, 33 informational
- **Status overview**: All 162 findings are active and verified; no findings have been mitigated, closed, or marked as false positives
- **SLA status**: No SLA breaches identified (no SLAs configured for this engagement)
- **Risk acceptance**: No findings have been risk-accepted
- **Top CWE categories**: CWE-119 (Improper Restriction of Operations within the Bounds of a Memory Buffer) appears frequently in critical findings
