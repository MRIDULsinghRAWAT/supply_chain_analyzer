<p align="center">
  <h1 align="center">🛡️ Supply Chain Security Analyzer</h1>
  <p align="center">
    <strong>A comprehensive, multi-ecosystem command-line toolkit for auditing software supply chain risks — from CVEs and secrets to typosquatting, license conflicts, and CI/CD misconfigurations.</strong>
  </p>
  <p align="center">
    <img src="https://img.shields.io/badge/python-3.8%2B-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python 3.8+">
    <img src="https://img.shields.io/badge/license-MIT-22C55E?style=for-the-badge" alt="MIT License">
    <img src="https://img.shields.io/badge/version-1.1.0-6366F1?style=for-the-badge" alt="Version 1.1.0">
    <img src="https://img.shields.io/badge/tests-30%20passing-22C55E?style=for-the-badge&logo=pytest&logoColor=white" alt="30 Tests Passing">
    <img src="https://img.shields.io/badge/scanners-8%20engines-EF4444?style=for-the-badge&logo=security&logoColor=white" alt="8 Security Engines">
  </p>
</p>

---

## 📖 Table of Contents

- [Why This Project?](#-why-this-project)
- [Features at a Glance](#-features-at-a-glance)
- [Supported Ecosystems](#-supported-ecosystems)
- [Architecture](#-architecture)
- [Getting Started](#-getting-started)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
- [Usage & CLI Reference](#-usage--cli-reference)
  - [Quick Start Examples](#quick-start-examples)
  - [All CLI Options](#all-cli-options)
- [Security Engines — Deep Dive](#-security-engines--deep-dive)
  - [Vulnerability Scanner (SCA)](#1-vulnerability-scanner-sca)
  - [Secrets Scanner](#2-secrets-scanner)
  - [Typosquatting Detector](#3-typosquatting-detector)
  - [License Compliance Tracker](#4-license-compliance-tracker)
  - [Dependency Confusion Scanner](#5-dependency-confusion-scanner)
  - [CI/CD Pipeline Auditor](#6-cicd-pipeline-auditor)
  - [Dockerfile & Artifact Scanner](#7-dockerfile--artifact-scanner)
  - [Version Staleness Analyzer](#8-version-staleness-analyzer)
- [Dependency Graph & Blast Radius](#-dependency-graph--blast-radius)
- [Terminal Dashboard](#-terminal-dashboard)
- [Output & Reporting](#-output--reporting)
- [CI/CD Integrations](#-cicd-integrations)
  - [Pre-Commit Hook](#pre-commit-hook)
  - [GitHub Actions](#github-actions)
  - [GitLab CI](#gitlab-ci)
- [Project Structure](#-project-structure)
- [Testing](#-testing)
- [Contributing](#-contributing)
- [License](#-license)

---

## 🤔 Why This Project?

Modern software projects rely on hundreds of third-party dependencies. Each one is a potential attack vector:

| Threat | Real-World Example |
|---|---|
| **Malicious packages** | `ua-parser-js` npm hijack (2021) — 8M weekly downloads compromised |
| **Typosquatting** | `python3-dateutil` mimicking `python-dateutil` on PyPI |
| **Leaked secrets** | Uber's 2016 breach — AWS keys committed to a GitHub repo |
| **License violations** | GPL-licensed transitive dependency in a proprietary SaaS product |
| **Dependency confusion** | Alex Birsan's 2021 proof-of-concept attack on Apple, Microsoft, PayPal |
| **CI/CD exploitation** | Codecov supply chain attack via compromised bash uploader script |

**Supply Chain Security Analyzer** detects all of these threats — and more — in a single scan, across Python, Node.js, Ruby, and Java ecosystems.

---

## ✨ Features at a Glance

| Category | Feature | Description |
|---|---|---|
| 🔍 **SCA** | CVE Scanning | Real-time queries against GitHub Advisory + NVD APIs with intelligent caching |
| 🕵️ **Secrets** | Credential Detection | 10+ regex patterns for API keys, tokens, private keys, and database URIs |
| 🕵️ **Secrets** | Git History Scan | Inspects the last 50 commits for secrets that were committed and later deleted |
| ⚠️ **Typosquatting** | 7-Algorithm Detection | Levenshtein distance, homoglyphs, char-swaps, repeated chars, combosquatting, separator confusion, version suffixes |
| 📋 **License** | Risk Classification | Maps licenses to Permissive / Copyleft / Proprietary risk tiers |
| 📋 **License** | Conflict Detection | Flags incompatible license combinations (e.g., GPL + proprietary) |
| 📦 **Dep Confusion** | Registry Audit | Scans `.npmrc` / `pip.conf` for misconfigured private registry indexes |
| 📦 **Dep Confusion** | Namespace Claiming | Checks if scoped private packages exist on public registries |
| 🛠️ **CI/CD** | Pipeline Audit | Detects `curl \| bash`, unpinned actions, and env secret exposure |
| 🐋 **Docker** | Artifact Scan | Flags `FROM latest`, missing `USER` directives, and hardcoded `ENV` secrets |
| 📈 **Versions** | Staleness Check | Compares installed versions against latest upstream releases |
| 🌳 **Graph** | Dependency Tree | BFS depth assignment, DFS cycle detection, ASCII tree visualization |
| 🌳 **Graph** | Blast Radius | Shortest-path tracing from direct dependencies to transitive vulnerabilities |
| 📊 **Dashboard** | Terminal TUI | Health score gauge, categorized findings, and prioritized action items |

---

## 🌐 Supported Ecosystems

| Parser | Manifest File | Ecosystem | What It Parses |
|---|---|---|---|
| `PythonParser` | `requirements.txt` | Python / PyPI | Version constraints, comments, inline options |
| `NpmParser` | `package.json` | Node.js / npm | `dependencies`, `devDependencies`, `peerDependencies`, `optionalDependencies`, and `node_modules/` transitive resolution |
| `RubyParser` | `Gemfile` | Ruby / RubyGems | `gem` declarations with version constraint patterns |
| `MavenParser` | `pom.xml` | Java / Maven | XML namespace handling, `<properties>` resolution, dependency scoping, `groupId:artifactId` naming |

---

## 🏗️ Architecture

The analyzer follows a clean **three-phase pipeline**: Parse → Scan → Report.

```
                         ┌─────────────────────────────────┐
                         │         CLI Entry Point          │
                         │       analyzer/main.py           │
                         └───────────────┬─────────────────┘
                                         │
          ┌──────────────────────────────┼──────────────────────────────┐
          ▼                              ▼                              ▼
   ╔══════════════════╗      ╔═══════════════════════╗      ╔══════════════════════════╗
   ║   PHASE 1: PARSE ║      ║  PHASE 1.5: GRAPH     ║      ║   PHASE 2: SCAN          ║
   ╠══════════════════╣      ╠═══════════════════════╣      ╠══════════════════════════╣
   ║ python_parser.py ║      ║ dependency_graph.py   ║      ║ vulnerability.py   (SCA) ║
   ║ npm_parser.py    ║      ║                       ║      ║ typosquatting.py         ║
   ║ ruby_parser.py   ║      ║ • BFS Depth Levels    ║      ║ secrets.py               ║
   ║ maven_parser.py  ║      ║ • DFS Cycle Detection ║      ║ license.py               ║
   ╚══════════════════╝      ║ • Shortest-Path Trace ║      ║ dep_confusion.py         ║
                              ║ • ASCII Tree Render   ║      ║ pipeline.py              ║
                              ╚═══════════════════════╝      ║ version_analyzer.py      ║
                                                              ║ artifact.py    (Docker)  ║
                                                              ╚═════════════┬════════════╝
                                                                            │
                                                                            ▼
                                                              ╔══════════════════════════╗
                                                              ║   PHASE 3: REPORT        ║
                                                              ╠══════════════════════════╣
                                                              ║ json_report.py           ║
                                                              ║ console.py               ║
                                                              ║ dashboard.py       (TUI) ║
                                                              ╚══════════════════════════╝
```

---

## 🚀 Getting Started

### Prerequisites

| Requirement | Version | Purpose |
|---|---|---|
| **Python** | 3.8+ | Runtime |
| **Git** | Any | Required for `--scan-git` commit history scanning |
| **pip** | Any | Package installation |

### Installation

```bash
# 1. Clone the repository
git clone https://github.com/MRIDULsinghRAWAT/supply_chain_analyzer.git
cd supply_chain_analyzer

# 2. Install Python dependencies
pip install -r requirements.txt

# 3. Install the CLI tool in editable mode
pip install -e .

# 4. Verify installation
scan-deps --help
```

> **Dependencies installed:** `python-Levenshtein==0.25.1`, `colorama==0.4.6`, `requests==2.31.0`, `packaging==23.2`

---

## 💻 Usage & CLI Reference

### Quick Start Examples

```bash
# ── Full Python scan with secrets, git history, dependency graph, and dashboard ──
scan-deps -f data/example_requirements.txt --scan-secrets -d . --scan-git --graph --dashboard

# ── Node.js scan with JSON report output ──
scan-deps -f data/example_package.json --scan-secrets -d . -o report.json --dashboard

# ── Scan only for secrets and CI/CD pipeline issues (no dependency file needed) ──
scan-deps -d . --scan-secrets --scan-git

# ── Quick scan skipping vulnerability and typosquatting checks ──
scan-deps -f requirements.txt --no-vuln --no-typo --dashboard

# ── Scan with limited dependency graph depth ──
scan-deps -f data/example_package.json --graph --graph-depth 3
```

### All CLI Options

```
usage: scan-deps [-h] [-f FILE] [-d DIRECTORY] [-o OUTPUT]
                 [--scan-secrets] [--scan-git] [--no-vuln] [--no-typo]
                 [--graph] [--graph-depth DEPTH] [--dashboard]

Supply Chain Security Analyzer — Audit your dependencies, secrets, and pipelines.

Options:
  -h, --help                Show this help message and exit

  -f, --file FILE           Path to a dependency manifest file:
                              • requirements.txt  (Python)
                              • package.json      (Node.js)
                              • Gemfile           (Ruby)
                              • pom.xml           (Java/Maven)

  -d, --directory DIR       Root directory to scan for secrets, CI/CD
                            pipeline configs, and Dockerfiles

  -o, --output FILE         Output JSON report path
                            (default: supply_chain_report.json)

  --scan-secrets            Enable secrets detection in source files
  --scan-git                Also scan git commit history for leaked secrets
  --no-vuln                 Skip CVE / vulnerability scanning
  --no-typo                 Skip typosquatting detection
  --graph                   Display the dependency tree visualization
  --graph-depth DEPTH       Limit dependency tree depth (default: unlimited)
  --dashboard               Render the terminal security dashboard
```

---

## 🔬 Security Engines — Deep Dive

### 1. Vulnerability Scanner (SCA)

Performs Software Composition Analysis by checking every dependency against known CVE databases.

| Feature | Detail |
|---|---|
| **Primary API** | GitHub Advisory Database (GraphQL) |
| **Fallback API** | NIST National Vulnerability Database (NVD REST) |
| **Caching** | Responses stored in `vulnerability_cache.json` for faster re-scans |
| **Offline Mode** | Falls back to a built-in mock database for popular packages |
| **Version Matching** | PEP 440-compliant via `packaging.specifiers.SpecifierSet` |

### 2. Secrets Scanner

Detects hardcoded credentials across your codebase and git history.

**Detected patterns include:**
- AWS Access Key IDs & Secret Keys
- GitHub / GitLab personal access tokens
- Slack webhooks & bot tokens
- Stripe API keys (live & test)
- Database connection URIs (`postgresql://`, `mongodb://`, `mysql://`)
- Generic passwords in config assignments
- RSA / DSA / EC private keys (PEM headers)

**Git history scanning:** Inspects diffs from the last 50 commits via `git show`, catching secrets that were committed and later removed.

> ℹ️ Test directories (`tests/`, `test/`) are automatically excluded to prevent mock tokens from triggering false positives.

### 3. Typosquatting Detector

Uses **7 prioritized detection algorithms** to identify packages that mimic popular, trusted libraries:

| # | Algorithm | Example Catch |
|---|---|---|
| 1 | Levenshtein Distance (≤2) | `reqeusts` → `requests` |
| 2 | Homoglyph Substitution | ` req𝘶ests` (Unicode 'u') → `requests` |
| 3 | Character Swap | `reuqests` → `requests` |
| 4 | Repeated Characters | `requestss` → `requests` |
| 5 | Combosquatting | `requests-secure` → `requests` |
| 6 | Separator Confusion | `request_s` vs `request-s` → `requests` |
| 7 | Version Suffix | `requests2` → `requests` |

Each match is scored by confidence, and results are ranked from highest to lowest risk.

### 4. License Compliance Tracker

Fetches license metadata from upstream registries and classifies risk:

| Risk Tier | License Examples | Action |
|---|---|---|
| 🟢 **Permissive** (Low) | MIT, Apache-2.0, BSD-2-Clause, ISC, Unlicense | No action needed |
| 🟡 **Weak Copyleft** (Medium) | LGPL-2.1, MPL-2.0, EPL-2.0 | Review usage scope |
| 🔴 **Strong Copyleft** (High) | GPL-2.0, GPL-3.0, AGPL-3.0, SSPL | Must open-source derivative works |
| ⚫ **Unknown / Proprietary** | No license detected | Investigate before shipping |

**Conflict detection:** Alerts when copyleft-licensed dependencies appear alongside proprietary code.

### 5. Dependency Confusion Scanner

Guards against dependency substitution attacks:

- **Registry audit:** Parses `.npmrc` (scoped registries) and `pip.conf` (`extra-index-url`) configurations
- **Namespace check:** Queries public registries (npm, PyPI) to verify whether private package names have been claimed publicly
- **Risk assessment:** Flags packages where a public registry version could shadow an internal one

### 6. CI/CD Pipeline Auditor

Scans build pipeline configurations for dangerous patterns:

| Pipeline Type | Config Files Scanned |
|---|---|
| GitHub Actions | `.github/workflows/*.yml` |
| GitLab CI | `.gitlab-ci.yml` |
| Jenkins | `Jenkinsfile` |

**Detected issues:**
- ⚠️ Shell piping: `curl https://... \| bash` (remote code execution risk)
- ⚠️ Unpinned actions: `uses: actions/checkout@main` instead of SHA-pinned refs
- ⚠️ Env secret exposure: Secrets passed via environment variables to shell steps
- ⚠️ Exfiltration patterns: Suspicious outbound data transfers

### 7. Dockerfile & Artifact Scanner

Audits container build configurations for security anti-patterns:

| Finding | Severity | Why It Matters |
|---|---|---|
| `FROM node:latest` | HIGH | Unpinned base image — builds become non-reproducible and vulnerable to tag mutation |
| No `USER` directive | MEDIUM | Container runs as root, expanding blast radius of any exploit |
| `ENV SECRET_KEY=...` | HIGH | Secrets baked into image layers are visible via `docker history` |
| `pip install --no-cache-dir` missing | LOW | Leaves package caches in the image, increasing attack surface |

### 8. Version Staleness Analyzer

Compares locally declared versions against the latest releases on upstream registries (PyPI, npm, RubyGems). Flags outdated dependencies that may be missing critical security patches, and caches results in `version_cache.json`.

---

## 🌳 Dependency Graph & Blast Radius

When you pass the `--graph` flag, the analyzer builds a full dependency tree with:

- **BFS depth assignment** — every node gets a depth level from the root
- **DFS cycle detection** — circular dependencies are identified and reported
- **ASCII tree visualization** — a clean, indented tree printed to the terminal
- **Transitive blast radius tracing** — when a vulnerability is found deep in the tree, the analyzer traces the **shortest path** back to the direct dependency you control, showing you exactly which import chain is affected

```
Example output:

📦 Dependency Tree (depth limited to 3):
├── flask==2.3.2
│   ├── werkzeug>=2.3.3
│   ├── jinja2>=3.1.2
│   │   └── markupsafe>=2.0
│   ├── itsdangerous>=2.1.2
│   └── click>=8.1.3
├── requests==2.31.0
│   ├── urllib3<3,>=1.21.1
│   ├── charset-normalizer<4,>=2
│   ├── idna<4,>=2.5
│   └── certifi>=2017.4.17
└── cryptography==41.0.0

⚠ Blast Radius: CVE-2023-XXXXX in urllib3
  → requests → urllib3  (2 hops from your direct dependency)
```

---

## 📊 Terminal Dashboard

Use `--dashboard` to render an interactive terminal UI showing:

```
╔═══════════════════════════════════════════════════════════════╗
║                 SUPPLY CHAIN HEALTH DASHBOARD                ║
╠═══════════════════════════════════════════════════════════════╣
║                                                               ║
║  Health Score: ██████████░░░░░░░░░░ 52/100                   ║
║                                                               ║
║  ┌─ Findings by Category ─────────────────────────────┐      ║
║  │  🔴 Vulnerabilities .............. 3                │      ║
║  │  🟡 Typosquatting Risks ......... 1                │      ║
║  │  🔴 Leaked Secrets .............. 2                │      ║
║  │  🟡 License Conflicts ........... 1                │      ║
║  │  🟢 Outdated Packages ........... 5                │      ║
║  └────────────────────────────────────────────────────┘      ║
║                                                               ║
║  Recommended Actions:                                         ║
║  1. Rotate leaked AWS key found in config.py:42               ║
║  2. Upgrade urllib3 to >=2.0.7 (CVE-2023-XXXXX)             ║
║  3. Pin GitHub Action to SHA: actions/checkout@<sha>          ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
```

---

## 📄 Output & Reporting

Every scan produces a comprehensive JSON report (default: `supply_chain_report.json`) containing:

```json
{
  "scan_metadata": {
    "timestamp": "2026-07-06T16:00:00Z",
    "file_scanned": "requirements.txt",
    "ecosystem": "python",
    "total_dependencies": 12
  },
  "vulnerabilities": [ ... ],
  "typosquatting_alerts": [ ... ],
  "secrets_found": [ ... ],
  "license_issues": [ ... ],
  "dependency_confusion_risks": [ ... ],
  "pipeline_findings": [ ... ],
  "artifact_findings": [ ... ],
  "version_staleness": [ ... ],
  "health_score": 52,
  "severity_summary": {
    "critical": 1,
    "high": 3,
    "medium": 5,
    "low": 8
  }
}
```

---

## 🔗 CI/CD Integrations

### Pre-Commit Hook

Add to your `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: local
    hooks:
      - id: supply-chain-scan
        name: Supply Chain Security Analyzer
        entry: scan-deps -f requirements.txt --scan-secrets -d .
        language: system
        files: ^(requirements\.txt|package\.json|Gemfile|pom\.xml)$
        pass_filenames: false
```

### GitHub Actions

Create `.github/workflows/scan.yml`:

```yaml
name: Supply Chain Security Scan
on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@692973e3d93d1497a1f264998ee64a54a59d7251 # v4.1.7
        with:
          fetch-depth: 0

      - name: Set up Python
        uses: actions/setup-python@f67e240f2867c4270ca87d100796396870d1e58e # v5.2.0
        with:
          python-version: '3.12'

      - name: Install & Scan
        run: |
          pip install -r requirements.txt
          pip install -e .
          scan-deps -f requirements.txt --scan-secrets --scan-git -d . -o supply_chain_report.json

      - name: Upload Report
        uses: actions/upload-artifact@834a144ee995460fba8ed112a2fc961b36a5ec5a # v4.3.6
        with:
          name: security-report
          path: supply_chain_report.json
```

> 🔒 All actions are pinned to immutable commit SHAs to prevent tag-mutation attacks.

### GitLab CI

Add to your `.gitlab-ci.yml`:

```yaml
supply-chain-scan:
  stage: test
  image: python:3.12-slim
  script:
    - pip install -r requirements.txt
    - pip install -e .
    - scan-deps -f requirements.txt --scan-secrets -d . -o supply_chain_report.json
  artifacts:
    paths:
      - supply_chain_report.json
    expire_in: 30 days
```

---

## 📂 Project Structure

```
supply-chain-analyzer/
├── analyzer/
│   ├── __init__.py
│   ├── main.py                    # CLI entry point & orchestration
│   ├── parsers/
│   │   ├── __init__.py
│   │   ├── python_parser.py       # requirements.txt parser
│   │   ├── npm_parser.py          # package.json + node_modules parser
│   │   ├── ruby_parser.py         # Gemfile parser
│   │   └── maven_parser.py        # pom.xml parser with property resolution
│   ├── scanners/
│   │   ├── __init__.py
│   │   ├── vulnerability.py       # CVE scanning (GitHub Advisory + NVD)
│   │   ├── typosquatting.py       # 7-algorithm typosquatting detection
│   │   ├── secrets.py             # Credential & secret pattern detection
│   │   ├── license.py             # License risk classification & conflicts
│   │   ├── dep_confusion.py       # Dependency confusion attack detection
│   │   ├── pipeline.py            # CI/CD pipeline security audit
│   │   ├── version_analyzer.py    # Version staleness checker
│   │   └── artifact.py            # Dockerfile security audit
│   ├── graph/
│   │   ├── __init__.py
│   │   └── dependency_graph.py    # BFS/DFS graph + blast radius tracing
│   └── reporters/
│       ├── __init__.py
│       ├── console.py             # Terminal color output
│       ├── json_report.py         # Structured JSON report generator
│       └── dashboard.py           # Terminal TUI health dashboard
├── data/
│   ├── example_requirements.txt   # Sample Python dependencies
│   ├── example_package.json       # Sample Node.js dependencies
│   ├── known_deps.json            # Known dependency resolution database
│   └── popular_packages.json      # Popular package names for typosquatting
├── tests/
│   ├── __init__.py
│   ├── test_parsers.py            # Parser unit tests
│   ├── test_scanners.py           # Core scanner tests
│   └── test_scanners_extended.py  # Extended scanner coverage tests
├── .github/
│   └── workflows/
│       └── scan.yml               # GitHub Actions CI workflow
├── .gitlab-ci.yml                 # GitLab CI configuration
├── .pre-commit-config.yaml        # Pre-commit hook configuration
├── .gitignore
├── requirements.txt               # Python dependencies
├── setup.py                       # Package setup with CLI entry point
├── LICENSE                        # MIT License
└── README.md                      # This file
```

---

## 🧪 Testing

The project includes **30 test cases** covering all parsers, scanners, and reporters:

```bash
# Run the full test suite
python -m pytest tests/ -v

# Run only parser tests
python -m pytest tests/test_parsers.py -v

# Run only scanner tests
python -m pytest tests/test_scanners.py tests/test_scanners_extended.py -v
```

**Test coverage includes:**
- ✅ All 4 parsers (Python, npm, Ruby, Maven)
- ✅ Vulnerability scanner with mock and cache scenarios
- ✅ Typosquatting detection across all 7 algorithms
- ✅ Secrets detection (file scanning + git history)
- ✅ License risk classification and conflict detection
- ✅ Dependency confusion registry audits
- ✅ CI/CD pipeline security checks
- ✅ Dockerfile artifact scanning
- ✅ Version staleness analysis
- ✅ Dependency graph building and cycle detection
- ✅ JSON report generation and structure validation

---

## 🤝 Contributing

Contributions are welcome! Here's how to get started:

1. **Fork** the repository
2. **Create** a feature branch: `git checkout -b feature/your-feature`
3. **Write tests** for any new functionality
4. **Ensure** all tests pass: `python -m pytest tests/ -v`
5. **Commit** with clear messages: `git commit -m "feat: add XYZ scanner"`
6. **Push** and open a Pull Request

### Adding a New Parser

1. Create a new parser in `analyzer/parsers/` following the existing pattern
2. The parser should expose a `parse(filepath)` method returning a list of `{"name": ..., "version": ...}` dicts
3. Register it in `analyzer/main.py` with the appropriate file extension detection
4. Add tests in `tests/test_parsers.py`

### Adding a New Scanner

1. Create a new scanner in `analyzer/scanners/`
2. Wire it into the scan pipeline in `analyzer/main.py`
3. Add test coverage in `tests/test_scanners_extended.py`

---

## 📜 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

```
MIT License — Copyright (c) 2026 Mridul
```

---

<p align="center">
  <sub>Built with 🐍 Python · Made for securing the software supply chain</sub>
</p>
