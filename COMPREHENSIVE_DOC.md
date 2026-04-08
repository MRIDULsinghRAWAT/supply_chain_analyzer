# Comprehensive Project Documentation: Supply Chain Analyzer

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
Ensure you are in the project root directory (`supply-chain-analyzer`).
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

The tool provides an intuitive command-line interface via `main.py` or the `scan-deps` command.

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
      - name: Upload Report
        uses: actions/upload-artifact@v2
        with:
          name: security-report
          path: security_report.json
```

## 8. Current Implementation Status

**Phase 1: High Priority (100% COMPLETE)**
- ✅ Python & npm Parsers (Transitive detection).
- ✅ Real CVE Database Integration (GitHub Advisory + NVD).
- ✅ Advanced Secrets Scanner (10+ patterns, Git & File parsing).
- ✅ JSON Structured Reporter & Console UI scoring.
- ✅ Unit Testing Suite (`test_parsers.py`, etc.).

**Phase 2/3: Medium & Advanced Priority (UPCOMING)**
- ⏳ Dependency Confusion Detection (detecting public vs private registry overlaps).
- ⏳ License Compliance Analysis.
- ⏳ Maven (`pom.xml`) and Ruby (`Gemfile`) Parsers.
- ⏳ Visual Dependency Graph Modeling.

## 9. Developer Guide

### Dependencies Added
- `requests (v2.31.0)`: For communicating with the GitHub Advisory API.
- `packaging (v23.2)`: Managing and interpreting complex Python packaging version constraints (PEP 440).
- `python-Levenshtein (v0.25.1)`: Fast character edit-distance computations for Typosquatting checks.
- `colorama (v0.4.6)`: For generating cross-platform colored terminal UI output.

### Running the Test Suite
The tool boasts strong code coverage via the `pytest` and `unittest` systems.
```bash
# Run pytest on the tests directory
python -m pytest tests/ -v

# Or use standard python unittest
python -m unittest discover -s tests -p "test_*.py"
```

## 10. Disclaimer
This tool is provided as-is for security analysis. While it helps identify common supply chain vulnerabilities, it should not be relied upon as the sole security solution. Always perform manual security reviews and follow industry best practices.

## 11. Codebase A-Z Breakdown: What it does and how it works

This section provides a complete, file-by-file technical breakdown of how the source code is architected to perform its security scans.

### `analyzer/main.py`
**What it does:** The central entry point and orchestrator for the CLI application.
**How it does it:** Uses Python's `argparse` to handle command-line flags. It acts as an orchestrator (following the Facade design pattern), conditionally invoking the relevant `Parser` based on the file extension (`.txt` -> `PythonParser`, `.json` -> `NpmParser`), aggregating dependencies, and piping those dependencies synchronously through the configured `Scanner` classes. It finalizes the process by pushing the results into the `Reporters`.

### `analyzer/parsers/npm_parser.py`
**What it does:** Extracts dependencies from Node.js projects, mapping primary and transitive dependencies.
**How it does it:** Loads `package.json` into a JSON dictionary and iterates across four distinct dependency arrays (`dependencies`, `devDependencies`, `peerDependencies`, `optionalDependencies`). To capture transitive (indirect) dependencies, it reads the local `node_modules/` directory natively using `os.listdir()` and parses sub-package JSON files to ensure offline mapping accuracy.

### `analyzer/parsers/python_parser.py`
**What it does:** Flattens Python packaging files into a generalized list of dependencies.
**How it does it:** Reads `requirements.txt` line-by-line, utilizing regular expressions (`r'^([a-zA-Z0-9\-_]+)(?:[=<>~]+(.*))?'`) to split the package name from standard PEP 440 version specifiers. It gracefully strips out comments and empty lines.

### `analyzer/reporters/console.py`
**What it does:** Manages stylized terminal stdout.
**How it does it:** Wraps Python's `print` functions in `colorama` ANSI escape formats (e.g., `Fore.RED`, `Style.BRIGHT`). Utilizing `@staticmethod` definitions, it decouples the styling logic completely from business logic to maintain standard UI guidelines.

### `analyzer/reporters/json_report.py`
**What it does:** Structures findings into a machine-readable JSON blob with a weighted security scoring algorithm.
**How it does it:** Initializes a nested Python dictionary (`self.report_data`). As vulnerabilities and secrets are fed into the class, it aggressively updates counters. It uses a custom `generate_security_score()` function that deducts points from 100 based on the detected severities (Critical: -15 pts, High: -8 pts, Medium: -3 pts, Low: -1 pt). Finally, it writes this dictionary to disk using the standard `json` module.

### `analyzer/scanners/secrets.py`
**What it does:** Operates as a static application security testing (SAST) engine designed strictly for high-entropy secrets and defined API tokens.
**How it does it:** Defines 10 pre-compiled native Python regular expression arrays corresponding to structural API keys (e.g., Slack Webhooks, AWS AKIA keys, stripe keys). 
- **File Scanning:** Opens non-binary files and uses `re.finditer` to locate regex matches efficiently, appending exact line numbers natively. 
- **Git Scanning:** Spawns a child shell via `subprocess.run(['git', 'log'])` and `subprocess.run(['git', 'show', commit])` to extract differential commit histories and pipes them through the regex engine to catch credentials committed and subsequently deleted over time.

### `analyzer/scanners/typosquatting.py`
**What it does:** Identifies if an installed package matches the naming syntax of a popular known-good package to prevent supply chain poisoning.
**How it does it:** Parses dependencies against an embedded offline dictionary (`data/popular_packages.json`). It applies the Levenshtein string-distance algorithm (`Levenshtein.distance(name, popular)`). If the edit distance is exactly 1 or 2 characters (e.g., `reqeusts` vs `requests`), an alert is triggered.

### `analyzer/scanners/vulnerability.py`
**What it does:** Responsible for establishing CVE correlation against dependencies dynamically.
**How it does it:** Defines GraphQL payloads to interface directly with the **GitHub Advisory API**, requesting known active CVE nodes corresponding to the provided ecosystem (pip or npm). It natively utilizes the `packaging` module (`SpecifierSet`, `pkg_version.parse`) to correctly assess if the local version falls within the vulnerable semantic version constraints. To optimize throughput and prevent IP-based API rate-limiting, responses correspond to a local `vulnerability_cache.json` hash map. It also implements an API fail-over routing directly to the **NVD JSON Service** endpoint.
