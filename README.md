# Supply Chain Security Analyzer

## 1. Project Overview
**Supply Chain Security Analyzer** is an advanced command-line tool written in Python 3 designed to inspect third-party dependencies, config files, and build pipelines to identify security vulnerabilities before they hit production. 

It implements a clean **Parse → Scan → Report** pipeline architecture, checking dependency manifests, configuration files, and build configurations.

### Key Capabilities
* 🛡️ **Software Composition Analysis (SCA)**: Real-time CVE scanning and PEP 440-compliant version matching against GitHub Advisories and the National Vulnerability Database.
* 🕵️‍♂️ **Secrets Exposure Detection**: Scans source files and Git commit history (diffs) for hardcoded credentials (AWS, Stripe, Slack, GitHub, Database URIs, passwords, etc.).
* ⚠️ **Typosquatting Detection**: Uses 7 custom, prioritized algorithms (Levenshtein, homoglyphs, char-swaps, repeated chars, combosquatting, separator confusion, and version suffixes) to identify mimicry of popular packages.
* 📋 **License Compliance & Conflict Tracker**: Classifies licenses (GPL, EPL, Apache-2.0, MIT, etc.) by risk and alerts on copyleft-proprietary license incompatibilities.
* 📦 **Dependency Confusion Detection**: Scans `.npmrc` and `pip.conf` index configs, checks public registries for namespaces, and detects unclaimed/vulnerable private packages.
* 🛠️ **CI/CD Pipeline Security Scanner**: Audits GitHub Actions, GitLab CI, and Jenkins configurations for shell command execution vulnerabilities (e.g. `curl | bash`), unpinned tags, and env-based exfiltration.
* 🐋 **Container & Artifact Analyzer**: Audits Dockerfiles for unpinned base image versions, root execution risks, and unsafe installation command patterns.
* 🌳 **Transitive Path Blast Radius Tracing**: Generates resolved dependency trees, detects cycles, and automatically traces shortest-paths from direct parent dependencies to transitive issues.
* 📊 **Interactive TUI Dashboard**: Visualizes health scores, metrics, categorised findings, and prioritized action plans inside a terminal dashboard.

---

## 2. Supported Ecosystems & Parsers

| Parser | Target File | Ecosystem | Notes |
|---|---|---|---|
| `PythonParser` | `requirements.txt` | Python / PyPI | Supports comment filtering and standard version constraints. |
| `NpmParser` | `package.json` | Node.js / npm | Parses all four dependency types; scans local `node_modules/` for transitive structures. |
| `RubyParser` | `Gemfile` | Ruby / RubyGems | Extracts gem declarations and version constraint patterns. |
| `MavenParser` | `pom.xml` | Java / Maven | Parses XML structures, resolves properties dynamically, handles Maven scopes, and constructs `groupId:artifactId` names. |

---

## 3. High-Level Architecture

```
                               ┌──────────────────────────┐
                               │       CLI Entry          │
                               │    (analyzer/main.py)    │
                               └────────────┬─────────────┘
                                            │
               ┌────────────────────────────┼───────────────────────────┐
               ▼                            ▼                           ▼
        [1. PARSING]                 [1.5 DEPS GRAPH]             [2. SCANNING ENGINES]
 ┌──────────────────────────┐  ┌──────────────────────────┐  ┌──────────────────────────┐
 │ • python_parser.py       │  │ • dependency_graph.py    │  │ • vulnerability.py (SCA) │
 │ • npm_parser.py          │  │                          │  │ • typosquatting.py       │
 │ • ruby_parser.py         │  │ - BFS Depth Assignment   │  │ • secrets.py             │
 │ • maven_parser.py        │  │ - DFS Cycle Detection    │  │ • license.py             │
 └──────────────────────────┘  │ - Shortest-Path Tracing  │  │ • dep_confusion.py       │
                               │ - ASCII Tree Drawing     │  │ • pipeline.py            │
                               └──────────────────────────┘  │ • version_analyzer.py    │
                                                             │ • artifact.py (Docker)   │
                                                             └──────────┬───────────────┘
                                                                        │
                                                                        ▼
                                                                  [3. REPORTING]
                                                             ┌──────────────────────────┐
                                                             │ • json_report.py         │
                                                             │ • console.py             │
                                                             │ • dashboard.py (TUI)     │
                                                             └──────────────────────────┘
```

---

## 4. Installation & Setup

### Prerequisites
* Python 3.8 or higher.
* Git installed (required for commit history scanning).

### Installation
Clone the repository and run the setup from the root directory:
```bash
# Install dependencies
pip install -r requirements.txt

# Install the package locally in editable mode (adds scan-deps command)
pip install -e .
```

---

## 5. Quick Start & CLI Reference

Run a full security scan on dependencies and search the current directory for secrets, pipelines, and Dockerfiles:
```bash
# Scan a Python project, visualize the dependency tree, and render the visual TUI dashboard
scan-deps -f data/example_requirements.txt --scan-secrets -d . --scan-git --graph --dashboard

# Scan an npm project and save a JSON report
scan-deps -f data/example_package.json --scan-secrets -d . -o report.json --dashboard
```

### CLI Command Options
```
usage: scan-deps [-h] [-f FILE] [-d DIRECTORY] [-o OUTPUT] [--scan-secrets] [--scan-git] [--no-vuln] [--no-typo] [--graph] [--graph-depth GRAPH_DEPTH] [--dashboard]

options:
  -h, --help            show this help message and exit
  -f FILE, --file FILE  Path to requirements.txt, package.json, Gemfile, or pom.xml
  -d DIRECTORY, --directory DIRECTORY
                        Scan entire directory for secrets, pipelines, and artifacts
  -o OUTPUT, --output OUTPUT
                        Output JSON report file path (default: supply_chain_report.json)
  --scan-secrets        Enable secret scanning
  --scan-git            Scan git history for secrets
  --no-vuln             Skip vulnerability scanning
  --no-typo             Skip typosquatting scanning
  --graph               Show dependency graph tree and stats box
  --graph-depth GRAPH_DEPTH
                        Max depth for graph tree (default: unlimited)
  --dashboard           Show terminal security dashboard
```

---

## 6. How the Security Engines Work

### 6.1 Vulnerability Scanner (SCA)
* **API Lookups**: Queries the GitHub Advisory GraphQL API and falls back to the National Vulnerability Database (NVD) REST API.
* **Intelligent Caching**: Saves API responses to `vulnerability_cache.json` to speed up subsequent scans.
* **Offline Mock Mode**: Automatically falls back to a mock database for popular packages if offline.
* **PEP 440 Version Matching**: Employs `packaging.specifiers.SpecifierSet` to accurately resolve constraints.

### 6.2 Secrets Scanner
* Scans files for 10 common secret pattern signatures (private keys, tokens, AWS keys, passwords).
* Inspects Git commit history (`git show` diffs of the last 50 commits) to catch secrets that were committed and later removed.
* Automatically ignores test directories (`tests/`, `test/`) to prevent mock testing tokens from triggering false positive alerts.

### 6.3 License Scanner
* Resolves licenses from package registries (PyPI, npm, RubyGems).
* Maps licenses to three risk tiers: Permissive (LOW), Unlicensed/Proprietary (MEDIUM), Copyleft (HIGH).
* Detects incompatibility conflicts (e.g. copyleft dependencies mixed with proprietary code).

### 6.4 Dependency Confusion Scanner
* Audits registry indexes (`.npmrc` scopes, `pip.conf` `extra-index-url` definitions).
* Queries public APIs to flag missing/unclaimed public package names mapping to scoped internal dependencies.

### 6.5 CI/CD Pipeline Audits
* Parses GitHub Actions workflows (`.github/workflows/*.yml`), GitLab CI (`.gitlab-ci.yml`), and Jenkinsfiles.
* Detects execution patterns like shell piping (`curl | bash`), env secrets exposure, and unpinned actions.

### 6.6 Dockerfile Scanner
* Verifies `Dockerfile` configurations.
* Triggers alerts on unpinned base images (e.g. `FROM node:latest`), hardcoded `ENV` secrets, missing `USER` directives (running as root), and unsafe package manager structures.

---

## 7. Integrations

### Git Pre-Commit Hook
Create a `.pre-commit-config.yaml` file in your repository:
```yaml
repos:
  - repo: local
    hooks:
      - id: scan-deps
        name: Supply Chain Dependency Analyzer
        entry: scan-deps -f requirements.txt --scan-secrets -d .
        language: system
        files: ^(requirements\.txt|package\.json|Gemfile|pom\.xml)$
        pass_filenames: false
```

### GitHub Actions Workflow (`.github/workflows/scan.yml`)
```yaml
name: Supply Chain Security Scan
on: [push, pull_request]
jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
    - name: Checkout repository
      uses: actions/checkout@692973e3d93d1497a1f264998ee64a54a59d7251 # v4.1.7
      with:
        fetch-depth: 0

    - name: Set up Python
      uses: actions/setup-python@f67e240f2867c4270ca87d100796396870d1e58e # v5.2.0
      with:
        python-version: '3.12'

    - name: Install dependencies
      run: |
        pip install -r requirements.txt
        pip install -e .

    - name: Run Scan
      run: scan-deps -f requirements.txt --scan-secrets --scan-git -d . -o supply_chain_report.json
```

---

## 8. Verification & Testing

### Running Tests
Execute the pytest suite (covering 30 test cases) verifying all parsers, scanners, and reporters:
```bash
python -m pytest tests/ -v
```

---

## 9. Disclaimer
This tool is provided as-is for security analysis. While it detects common supply chain vulnerabilities, it should not be relied upon as the sole security solution. Always perform manual security reviews and follow industry best practices.

