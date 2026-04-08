# Supply Chain Analyzer

## 1. Project Overview
**Supply Chain Analyzer** is a comprehensive Python-based security analysis tool for detecting supply chain vulnerabilities in project dependencies. It performs advanced security scanning on project dependencies (such as Python's `requirements.txt` and Node's `package.json`) to identify:
- **Typosquatting attacks**: Detecting packages with names similar to popular packages.
- **Known vulnerabilities (SCA)**: Identifying packages with known security vulnerabilities using real-time CVE correlation (GitHub Advisory API & NVD).
- **Secret exposure**: Scanning code and git history for accidentally committed secrets (API keys, tokens, etc.).
- **Dependency analysis**: Parsing and analyzing project dependency files, including transitive dependencies.

## 2. Key Features and Capabilities

✅ **Multi-Package Manager Support**
- **Python**: Analyze `requirements.txt` and `setup.py`.
- **npm**: Analyze `package.json` with support for `devDependencies`, `peerDependencies`, and `optionalDependencies`.
- **Transitive Dependencies**: Deep scanning into `node_modules/` to catch indirect vulnerabilities.

🔍 **Advanced Security Scanning**
- **Vulnerability Scanner**: Real-time checking against the GitHub Advisory API and National Vulnerability Database (NVD). Includes PEP 440 compliant version constraint checking and intelligent caching to minimize API calls.
- **Typosquatting Scanner**: Utilizes Levenshtein distance metrics to detect lookalike package names against a database of 40+ popular packages.
- **Secrets Scanner**: Detects 10+ patterns including AWS keys, GitHub tokens, Private keys (RSA/PGP), Database strings, Slack webhooks, JWT tokens, and Passwords. It can scan single files, entire directories recursively, and even Git history (up to the last 50 commits).

📊 **Comprehensive Reporting System**
- **Console Output**: Color-coded, human-readable terminal reports.
- **JSON Export**: Structured JSON report generation containing metadata, execution timestamps, severity breakdowns, and detailed vulnerability tracking.
- **Security Scoring System**: Generates a 0-100 metric for project health.
- **Remediation**: Recommends actionable fixes for discovered vulnerabilities.

## 3. Project Architecture

The application is structured into four main components:
- **Parsers (`analyzer/parsers/`)**: Handles reading and tokenizing dependency formats (e.g., `PythonParser`, `NpmParser`).
- **Scanners (`analyzer/scanners/`)**: Modular scanning engines that perform the actual threat detection (`TyposquattingScanner`, `VulnerabilityScanner`, `SecretsScanner`).
- **Reporters (`analyzer/reporters/`)**: Output formatters for structuring the results (`ConsoleReporter`, `JsonReporter`).
- **Data & Testing**: Local databases (`popular_packages.json`), example targets, and pytest-based test suites.

## 4. Installation & Quick Start

### Installation
Ensure you are in the project root directory.
```bash
# Install required dependencies
pip install -r requirements.txt

# Install the package locally in editable mode
pip install -e .
```
> *Note: Installing via `pip install -e .` sets up the `scan-deps` CLI entry point.*

### Basic Quick Start
```bash
# Scan a Python project
scan-deps -f requirements.txt

# Scan an npm project with secret scanning enabled
scan-deps -f package.json --scan-secrets

# Full directory scan + Git history scan with JSON output
scan-deps -d . --scan-secrets --scan-git -o complete_report.json
```

## 5. Usage & CLI Reference

| Command | Description |
|---------|-------------|
| `-f, --file` | Path to dependency file (`requirements.txt` or `package.json`) |
| `-d, --directory` | Scan entire directory for secrets |
| `-o, --output` | Output JSON report file path (default: `supply_chain_report.json`) |
| `--scan-secrets`| Enable secret scanning (looks for hardcoded credentials) |
| `--scan-git` | Scan git history for secrets (requires git) |
| `--no-vuln` | Skip vulnerability scanning |
| `--no-typo` | Skip typosquatting scanning |

## 6. How Scanning Works (Deep Dive)

### 6.1 Vulnerability Detection Lifecycle
1. **Parsing**: The provided dependency file is tokenized. Version numbers are extracted and normalized.
2. **Cache Check**: The tool queries a local `vulnerability_cache.json` to prevent duplicate API calls for previously scanned versions.
3. **API Query**: If the version isn't cached, it queries the **GitHub Advisory API** (and falls back to **NVD**).
4. **Severity Mapping**: Vulnerabilities are tagged with industry-standard severities:
   - 🔴 **CRITICAL** (15 pts deduction): Active exploits, leaked keys.
   - 🟠 **HIGH** (8 pts deduction): Exploitable CVEs, typosquatting, DB credentials.
   - 🟡 **MEDIUM** (3 pts deduction): Moderate impact, weak tokens.
   - 🟢 **LOW** (1 pt deduction): Informational.

### 6.2 Secret Detection Lifecycle
Utilizing robust regular expressions, the `SecretsScanner` traverses designated files or Git objects, looking for known credential entropy and patterns. It automatically filters binary files and standard media extensions to ensure optimal performance. Git scanning involves looking through recent commit diffs.

## 7. CI/CD Integration

To continually detect supply chain issues, the tool can be integrated into CI/CD pipelines natively as a GitHub Action.

**Example: GitHub Actions (`.github/workflows/security-scan.yml`)**
```yaml
name: Supply Chain Security Scan
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - uses: actions/setup-python@v2
      - name: Install
        run: pip install -e .
      - name: Run Security Scan
        run: scan-deps -f requirements.txt --scan-secrets -o security_report.json
```

## 8. Development & Testing
The tool boasts strong code coverage via the `pytest` and `unittest` systems.
```bash
# Run pytest on the tests directory
python -m pytest tests/ -v
```

## 9. Disclaimer
This tool is provided as-is for security analysis. While it helps identify common supply chain vulnerabilities, it should not be relied upon as the sole security solution. Always perform manual security reviews and follow industry best practices.
