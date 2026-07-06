# Supply Chain Security Analyzer

A command-line tool that audits software dependencies, source code, and build pipelines to detect supply chain security risks. Supports Python, Node.js, Ruby, and Java ecosystems.

---

## Table of Contents

- [What It Does](#what-it-does)
- [Supported Ecosystems](#supported-ecosystems)
- [Installation](#installation)
- [Usage](#usage)
- [CLI Options](#cli-options)
- [Security Scanners](#security-scanners)
- [Dependency Graph](#dependency-graph)
- [Terminal Dashboard](#terminal-dashboard)
- [Project Structure](#project-structure)
- [Testing](#testing)
- [License](#license)

---

## What It Does

This tool reads your dependency manifest file, builds a dependency graph, and runs 8 security scanners against your project:

1. **Vulnerability Scanner (SCA)** — checks dependencies against CVE databases (GitHub Advisory + NVD)
2. **Secrets Scanner** — detects hardcoded API keys, tokens, and passwords in files and git history
3. **Typosquatting Detector** — uses 7 algorithms to catch packages mimicking popular libraries
4. **License Compliance Tracker** — classifies license risk and detects copyleft conflicts
5. **Dependency Confusion Scanner** — audits registry configs for substitution attack risks
6. **CI/CD Pipeline Auditor** — flags dangerous patterns in GitHub Actions, GitLab CI, Jenkinsfiles
7. **Dockerfile Scanner** — catches unpinned images, root execution, and baked-in secrets
8. **Version Staleness Analyzer** — compares installed versions against latest upstream releases

It then generates a JSON report with a health score and recommended actions.

---

## Supported Ecosystems

| Parser | Manifest File | Ecosystem |
|---|---|---|
| `PythonParser` | `requirements.txt` | Python / PyPI |
| `NpmParser` | `package.json` | Node.js / npm |
| `RubyParser` | `Gemfile` | Ruby / RubyGems |
| `MavenParser` | `pom.xml` | Java / Maven |

---

## Installation

Requires **Python 3.8+** and **Git** (for git history scanning).

```bash
# Clone the repo
git clone https://github.com/MRIDULsinghRAWAT/supply_chain_analyzer.git
cd supply_chain_analyzer

# Install dependencies
pip install -r requirements.txt

# Install the CLI tool
pip install -e .

# Verify
scan-deps --help
```

---

## Usage

### Basic Examples

```bash
# Full Python scan — secrets, git history, dependency graph, and dashboard
scan-deps -f data/example_requirements.txt --scan-secrets -d . --scan-git --graph --dashboard

# Node.js scan with JSON report
scan-deps -f data/example_package.json --scan-secrets -d . -o report.json --dashboard

# Scan only secrets and pipelines (no dependency file needed)
scan-deps -d . --scan-secrets --scan-git

# Quick scan — skip vulnerability and typosquatting checks
scan-deps -f requirements.txt --no-vuln --no-typo --dashboard
```

### Running on Real Projects

Replace the paths in these commands with the absolute or relative path to your real project files.

```bash
# Python Project (requirements.txt)
scan-deps -f /path/to/your/project/requirements.txt --scan-secrets -d /path/to/your/project --scan-git --graph --dashboard

# Node.js Project (package.json)
scan-deps -f /path/to/your/project/package.json --scan-secrets -d /path/to/your/project --scan-git --graph --dashboard

# Ruby Project (Gemfile)
scan-deps -f /path/to/your/project/Gemfile --scan-secrets -d /path/to/your/project --scan-git --graph --dashboard

# Java/Maven Project (pom.xml)
scan-deps -f /path/to/your/project/pom.xml --scan-secrets -d /path/to/your/project --scan-git --graph --dashboard

# Directory Secret Scan Only (No manifest file needed)
scan-deps -d /path/to/your/project --scan-secrets --scan-git
```


---

## CLI Options

```
scan-deps [-h] [-f FILE] [-d DIRECTORY] [-o OUTPUT]
          [--scan-secrets] [--scan-git] [--no-vuln] [--no-typo]
          [--graph] [--graph-depth DEPTH] [--dashboard]

  -f, --file FILE           Dependency manifest file (requirements.txt, package.json, Gemfile, pom.xml)
  -d, --directory DIR       Directory to scan for secrets, pipelines, and Dockerfiles
  -o, --output FILE         Output JSON report path (default: supply_chain_report.json)
  --scan-secrets            Enable secret detection in source files
  --scan-git                Scan git commit history for leaked secrets
  --no-vuln                 Skip vulnerability scanning
  --no-typo                 Skip typosquatting detection
  --graph                   Show dependency tree visualization
  --graph-depth DEPTH       Limit tree depth (default: unlimited)
  --dashboard               Show terminal security dashboard
```

---

## Security Scanners

### Vulnerability Scanner (SCA)
- Queries GitHub Advisory Database (GraphQL) and NVD (REST) APIs
- Caches responses in `vulnerability_cache.json` for faster re-scans
- Falls back to built-in mock data when offline
- Uses PEP 440-compliant version matching via `packaging.specifiers`

### Secrets Scanner
- Detects 10+ patterns: AWS keys, GitHub/GitLab tokens, Slack webhooks, Stripe keys, database URIs, private keys, passwords
- Scans git history (last 50 commits) to catch deleted secrets
- Automatically excludes `tests/` and `test/` directories

### Typosquatting Detector
Uses 7 algorithms ranked by priority:

| Algorithm | Example |
|---|---|
| Levenshtein distance | `reqeusts` vs `requests` |
| Homoglyph substitution | Unicode look-alikes |
| Character swap | `reuqests` vs `requests` |
| Repeated characters | `requestss` vs `requests` |
| Combosquatting | `requests-secure` vs `requests` |
| Separator confusion | `request_s` vs `request-s` |
| Version suffix | `requests2` vs `requests` |

### License Compliance Tracker
- Fetches license metadata from PyPI, npm, and RubyGems
- Classifies into risk tiers: Permissive (low), Weak Copyleft (medium), Strong Copyleft (high), Unknown (investigate)
- Detects incompatible license combinations

### Dependency Confusion Scanner
- Parses `.npmrc` and `pip.conf` registry configurations
- Checks if private package names exist on public registries
- Flags potential namespace hijacking risks

### CI/CD Pipeline Auditor
- Scans `.github/workflows/*.yml`, `.gitlab-ci.yml`, and `Jenkinsfile`
- Detects shell piping (`curl | bash`), unpinned action tags, env secret exposure, and exfiltration patterns

### Dockerfile Scanner
- Flags unpinned base images (`FROM node:latest`)
- Detects missing `USER` directives (running as root)
- Catches hardcoded secrets in `ENV` instructions

### Version Staleness Analyzer
- Compares local versions against latest releases on PyPI, npm, RubyGems
- Caches results in `version_cache.json`

---

## Dependency Graph

With the `--graph` flag, the tool builds a full dependency tree:

- **BFS depth assignment** — assigns depth levels from root
- **DFS cycle detection** — identifies circular dependencies
- **ASCII tree** — renders a clean indented tree in the terminal
- **Blast radius tracing** — traces the shortest path from a vulnerable transitive dependency back to the direct dependency you control

---

## Terminal Dashboard

The `--dashboard` flag renders a terminal UI showing:

- Health score gauge (0-100) with color-coded status
- Findings summary table across all 8 scanner categories
- Severity breakdown (Critical / High / Medium / Low)
- Prioritized remediation recommendations

---

## Project Structure

```
supply-chain-analyzer/
├── analyzer/
│   ├── __init__.py
│   ├── main.py                    # CLI entry point and orchestration
│   ├── parsers/
│   │   ├── python_parser.py       # requirements.txt parser
│   │   ├── npm_parser.py          # package.json + node_modules parser
│   │   ├── ruby_parser.py         # Gemfile parser
│   │   └── maven_parser.py        # pom.xml parser
│   ├── scanners/
│   │   ├── vulnerability.py       # CVE scanning (GitHub Advisory + NVD)
│   │   ├── typosquatting.py       # 7-algorithm typosquatting detection
│   │   ├── secrets.py             # Credential detection
│   │   ├── license.py             # License risk classification
│   │   ├── dep_confusion.py       # Dependency confusion detection
│   │   ├── pipeline.py            # CI/CD pipeline audit
│   │   ├── version_analyzer.py    # Version staleness checker
│   │   └── artifact.py            # Dockerfile audit
│   ├── graph/
│   │   └── dependency_graph.py    # BFS/DFS graph + blast radius tracing
│   └── reporters/
│       ├── console.py             # Colored terminal output
│       ├── json_report.py         # JSON report generator
│       └── dashboard.py           # Terminal dashboard
├── data/
│   ├── example_requirements.txt   # Sample Python dependencies
│   ├── example_package.json       # Sample Node.js dependencies
│   ├── known_deps.json            # Known dependency database
│   └── popular_packages.json      # Popular packages for typosquatting
├── tests/
│   ├── test_parsers.py            # Parser tests
│   ├── test_scanners.py           # Scanner tests
│   └── test_scanners_extended.py  # Extended scanner tests
├── requirements.txt
├── setup.py
├── LICENSE
└── README.md
```

---

## Testing

30 test cases covering all parsers, scanners, and reporters:

```bash
# Run full test suite
python -m pytest tests/ -v

# Run only parser tests
python -m pytest tests/test_parsers.py -v

# Run only scanner tests
python -m pytest tests/test_scanners.py tests/test_scanners_extended.py -v
```

---

## License

MIT License - Copyright (c) 2026 Mridul. See [LICENSE](LICENSE) for details.
