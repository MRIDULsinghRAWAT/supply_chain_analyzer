# 🚀 Quick Start Guide

## Installation (2 minutes)

```bash
# 1. Navigate to project directory
cd supply-chain-analyzer

# 2. Install dependencies
pip install -r requirements.txt

# 3. Install package with CLI entry point
pip install -e .
```

## Basic Usage Examples

### 1️⃣ Scan Python Project
```bash
python analyzer/main.py -f requirements.txt
```

### 2️⃣ Scan npm Project
```bash
python analyzer/main.py -f package.json
```

### 3️⃣ Scan for Secrets in Directory
```bash
python analyzer/main.py -d . --scan-secrets
```

### 4️⃣ Scan Git History for Secrets
```bash
python analyzer/main.py -f requirements.txt --scan-git
```

### 5️⃣ Full Analysis with JSON Report
```bash
python analyzer/main.py -f requirements.txt --scan-secrets --scan-git -o security_report.json
```

### 6️⃣ Using CLI Command (after installation)
```bash
scan-deps -f requirements.txt -o report.json
```

## Command Reference

| Command | Purpose |
|---------|---------|
| `-f, --file` | Path to requirements.txt or package.json |
| `-d, --directory` | Scan directory for secrets |
| `-o, --output` | Save JSON report (default: supply_chain_report.json) |
| `--scan-secrets` | Enable secret scanning |
| `--scan-git` | Scan git history for secrets |
| `--no-vuln` | Skip vulnerability scanning |
| `--no-typo` | Skip typosquatting scanning |

## Output Examples

### Console Output
```
=== Starting Analysis on requirements.txt ===
[+] Successfully parsed 15 dependencies.

=== Scanning for Typosquatting ===
[+] No typosquatting detected.

=== Scanning for Vulnerabilities (SCA) ===
[!] ALERT: requests (v2.25.1) - [MEDIUM] CVE-2018-18074

=== Generating Report ===
[+] JSON report saved to supply_chain_report.json
```

### JSON Report
Generated file includes:
- ✓ Metadata (timestamp, security score)
- ✓ Summary (total issues, severity breakdown)
- ✓ All dependencies and versions
- ✓ Vulnerabilities with CVE IDs
- ✓ Typosquatting alerts
- ✓ Secrets found with locations
- ✓ Remediation recommendations

## Test the Tool

### Test with Example Files
```bash
# Test Python scanning
python analyzer/main.py -f data/example_requirements.txt

# Test npm scanning  
python analyzer/main.py -f data/example_package.json

# Test secret detection
python analyzer/main.py -f data/example_requirements.txt --scan-secrets
```

### Run Unit Tests
```bash
python -m pytest tests/ -v
```

## Security Levels Explained

🔴 **CRITICAL** (15 points deducted)
- Actively exploited vulnerabilities
- Leaked API keys / private keys
- Remote code execution risks

🟠 **HIGH** (8 points deducted)
- Exploitable vulnerabilities
- Typosquatting packages
- Database credentials

🟡 **MEDIUM** (3 points deducted)
- Moderate impact vulnerabilities
- Weak JWT tokens
- Slackbots

🟢 **LOW** (1 point deducted)
- Low-impact issues
- Informational findings

## Workflow Integration

### Before Commit
```bash
# Quick scan for secrets before committing
python analyzer/main.py -f requirements.txt --scan-secrets
```

### CI/CD Pipeline Example
```yaml
name: Security Scan
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - uses: actions/setup-python@v2
      - name: Install dependencies
        run: pip install -e .
      - name: Run security scan
        run: scan-deps -f requirements.txt -o report.json
      - name: Upload report
        uses: actions/upload-artifact@v2
        with:
          name: security-report
          path: report.json
```

## What Gets Detected?

### 🎯 Vulnerabilities
- ✓ CVEs from GitHub Advisory API
- ✓ National Vulnerability Database (NVD)
- ✓ Version constraint checking
- ✓ Transitive dependencies

### 🔍 Typosquatting
- ✓ Similar package names (Levenshtein distance)
- ✓ Common typos detected
- ✓ 40+ popular packages in database

### 🔐 Secrets
- ✓ AWS keys
- ✓ GitHub tokens
- ✓ Private keys
- ✓ API keys / Stripe keys
- ✓ Database credentials
- ✓ JWT tokens
- ✓ Passwords
- ✓ Slack webhooks

## Tips & Tricks

### 1. Generate Report Only (no console output)
```bash
python analyzer/main.py -f requirements.txt -o report.json 2>/dev/null
```

### 2. Scan Multiple Files
```bash
for file in requirements*.txt; do
  python analyzer/main.py -f "$file" -o "report_$file.json"
done
```

### 3. Check Specific Package
```bash
# Create requirements-check.txt with single package
echo "django==3.2.0" > requirements-check.txt
python analyzer/main.py -f requirements-check.txt
```

### 4. Export for Analysis
```bash
python analyzer/main.py -f requirements.txt -o report.json
jq '.vulnerabilities[]' report.json  # Filter vulnerabilities
```

## Troubleshooting

**Issue**: `ModuleNotFoundError`
```bash
# Solution: Reinstall package in development mode
pip install -e .
```

**Issue**: `requests` library not found
```bash
# Solution: Install dependencies
pip install -r requirements.txt
```

**Issue**: GitHub API rate limit
```bash
# Solution: Vulnerability cache system handles this
# Cached results stored in vulnerability_cache.json
```

**Issue**: Windows secret scanning doesn't work
```bash
# Solution: Use --scan-secrets with absolute paths
python analyzer/main.py -f "C:\path\to\requirements.txt" --scan-secrets
```

## Next Steps

1. **Integrate into CI/CD** - Add to GitHub Actions, GitLab CI, or Jenkins
2. **Setup pre-commit hooks** - Scan before every commit
3. **Monitor vulnerabilities** - Re-run scans periodically
4. **Review reports** - Check JSON reports for remediation
5. **Update packages** - Fix identified vulnerabilities

## Support & Resources

- 📖 Full README: `README.md`
- 📋 Implementation Summary: `IMPLEMENTATION_SUMMARY.md`
- 🧪 Tests: `tests/`
- 📊 Example data: `data/`

---

**Ready to secure your supply chain? Start scanning now! 🔒**
