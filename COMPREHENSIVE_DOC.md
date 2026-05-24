# Supply Chain Analyzer — Comprehensive Project Documentation

> **Version**: 1.1.0 &nbsp;|&nbsp; **License**: MIT &nbsp;|&nbsp; **Author**: Mridul &nbsp;|&nbsp; **Language**: Python 3

---

## Table of Contents

1. [What Is This Project?](#1-what-is-this-project)
2. [What Problem Does It Solve?](#2-what-problem-does-it-solve)
3. [High-Level Architecture](#3-high-level-architecture)
4. [Complete File & Folder Map](#4-complete-file--folder-map)
5. [Dependencies (What Libraries It Uses & Why)](#5-dependencies-what-libraries-it-uses--why)
6. [Deep Dive: Every Module Explained](#6-deep-dive-every-module-explained)
   - 6.1 [Entry Point — `analyzer/main.py`](#61-entry-point--analyzermainpy)
   - 6.2 [Parsers — Reading Dependency Files](#62-parsers--reading-dependency-files)
   - 6.3 [Scanners — The Security Engines](#63-scanners--the-security-engines)
   - 6.4 [Reporters — Presenting the Results](#64-reporters--presenting-the-results)
7. [Data Files](#7-data-files)
8. [How the 3-Phase Pipeline Works (End-to-End Data Flow)](#8-how-the-3-phase-pipeline-works-end-to-end-data-flow)
9. [The Security Scoring System](#9-the-security-scoring-system)
10. [CLI Reference & Usage Examples](#10-cli-reference--usage-examples)
11. [Tests](#11-tests)
12. [CI/CD Integration](#12-cicd-integration)
13. [Key Design Decisions & Trade-offs](#13-key-design-decisions--trade-offs)
14. [Glossary of Terms](#14-glossary-of-terms)

---

## 1. What Is This Project?

**Supply Chain Analyzer** is a command-line security tool that inspects the *dependencies* (third-party libraries) of a Python or Node.js project and tries to find security problems before they become real incidents.

Think of it as a security guard for your `requirements.txt` (Python) or `package.json` (Node/npm). You point the tool at your dependency file, and it automatically:

- Checks if any of those packages have **known vulnerabilities** (CVEs).
- Checks if any package name looks suspiciously like a popular package (**typosquatting** — a common supply chain attack).
- Scans your source code and even your **Git history** for accidentally committed **secrets** (API keys, passwords, tokens, private keys, etc.).
- Generates a **security score** from 0 to 100 and a detailed **JSON report** with remediation recommendations.

---

## 2. What Problem Does It Solve?

Modern software projects pull in tens or hundreds of third-party packages. This creates a *supply chain* — a chain of trust where your app depends on code written by strangers on the internet. Attackers exploit this in several ways:

| Attack Type | How It Works | Real-World Example |
|---|---|---|
| **Known Vulnerabilities (SCA)** | A package you depend on has a publicly disclosed security bug (CVE). Your app inherits that vulnerability. | The `requests` library had CVE-2018-18074 — an information-exposure bug in versions below 2.20.0. |
| **Typosquatting** | An attacker publishes a malicious package with a name almost identical to a popular one (`requets` instead of `requests`). A developer installs it by accident. | `python3-dateutil` mimicking `python-dateutil` on PyPI. |
| **Secret Exposure** | A developer accidentally commits an AWS key, database password, or API token into source code or Git history. Attackers scan public repos for these. | Uber's 2016 breach started with AWS credentials found in a GitHub repo. |

This tool detects all three of these attack vectors in a single scan.

---

## 3. High-Level Architecture

The project follows a clean **Pipeline Architecture** with three phases: **Parse → Scan → Report**.

```
┌─────────────────────────────────────────────────────────────────────┐
│                          CLI (main.py)                              │
│                    argparse-based entry point                       │
└───────────┬───────────────────┬───────────────────┬─────────────────┘
            │                   │                   │
     ┌──────▼──────┐    ┌──────▼──────┐     ┌──────▼──────┐
     │   PHASE 1   │    │   PHASE 2   │     │   PHASE 3   │
     │   PARSING   │    │  SCANNING   │     │  REPORTING  │
     └──────┬──────┘    └──────┬──────┘     └──────┬──────┘
            │                  │                   │
  ┌─────────┴────────┐   ┌────┴──────────────┐   ┌┴──────────────┐
  │  PythonParser    │   │ TyposquattingScnr │   │ ConsoleRptr   │
  │  (requirements)  │   │ VulnerabilityScnr │   │ JsonReporter  │
  │                  │   │ SecretsScanner    │   │               │
  │  NpmParser       │   │                   │   │               │
  │  (package.json)  │   │                   │   │               │
  └──────────────────┘   └───────────────────┘   └───────────────┘
```

Each component is in its own file and can be used independently or swapped out for a different implementation.

---

## 4. Complete File & Folder Map

Here is every file in the project with its purpose:

```
supply-chain-analyzer/
│
├── analyzer/                          # ← Main application package
│   ├── __init__.py                    # Makes `analyzer` a Python package (empty)
│   ├── main.py                        # CLI entry point — wires everything together
│   │
│   ├── parsers/                       # PHASE 1: Read & tokenize dependency files
│   │   ├── __init__.py                # Makes `parsers` a sub-package (empty)
│   │   ├── python_parser.py           # Parses requirements.txt files
│   │   └── npm_parser.py              # Parses package.json files + node_modules
│   │
│   ├── scanners/                      # PHASE 2: Detect security issues
│   │   ├── __init__.py                # Makes `scanners` a sub-package (empty)
│   │   ├── typosquatting.py           # Multi-technique typosquatting detector (7 checks)
│   │   ├── vulnerability.py           # Checks CVE databases for known vulns
│   │   └── secrets.py                 # Finds hardcoded secrets in files & git
│   │
│   ├── graph/                         # PHASE 1.5: Dependency graph analysis
│   │   ├── __init__.py                # Makes `graph` a sub-package (empty)
│   │   └── dependency_graph.py        # Builds, analyses, and visualizes dep graph
│   │
│   └── reporters/                     # PHASE 3: Format & output results
│       ├── __init__.py                # Makes `reporters` a sub-package (empty)
│       ├── console.py                 # Color-coded terminal output
│       └── json_report.py             # Structured JSON report with scoring
│
├── data/                              # Static data files used by scanners
│   ├── popular_packages.json          # Ecosystem-aware database of 145 popular package names
│   ├── known_deps.json                # Transitive dependency metadata for ~70 popular packages
│   ├── example_requirements.txt       # Sample Python dependency file for testing
│   └── example_package.json           # Sample npm dependency file for testing
│
├── tests/                             # Automated test suite
│   ├── __init__.py                    # Makes `tests` a package (empty)
│   ├── test_parsers.py                # Unit tests for parsers, scanners, graph, reporters
│   └── test_scanners.py               # Placeholder for scanner-specific tests (empty)
│
├── setup.py                           # Package installer — defines `scan-deps` CLI command
├── requirements.txt                   # Python dependencies for this tool itself
├── LICENSE                            # MIT License
├── README.md                          # Project overview and usage guide
├── COMPREHENSIVE_DOC.md               # ← This file
├── PROJECT_PROGRESS.md                # Detailed spec-vs-implementation progress tracker
├── .gitignore                         # Files/folders Git should ignore
│
├── supply_chain_report.json           # Generated output — last scan's JSON report
└── vulnerability_cache.json           # Local cache of API vulnerability lookups
```

**Total source code**: ~1,500 lines across 9 core Python modules.

---

## 5. Dependencies (What Libraries It Uses & Why)

The tool has only **4 external dependencies**, defined in both `requirements.txt` and `setup.py`:

| Library | Version | What It Does in This Project |
|---|---|---|
| `python-Levenshtein` | 0.25.1 | Calculates the *edit distance* between two strings — used by the Typosquatting Scanner to measure how similar a package name is to a known popular one. |
| `colorama` | 0.4.6 | Makes colored terminal output work cross-platform (especially on Windows). Used by the Console Reporter to show green ✓, yellow ⚠, and red ✗ messages. |
| `requests` | 2.31.0 | Python's go-to HTTP library. Used by the Vulnerability Scanner to call the GitHub Advisory API and NVD API. |
| `packaging` | 23.2 | Provides PEP 440-compliant version parsing and specifier matching. Used to check if a package's installed version falls within a vulnerability's affected version range. |

The project also uses these **standard library modules** (no install needed): `argparse`, `os`, `re`, `json`, `subprocess`, `tempfile`, `unittest`, `datetime`, `sys`, `collections`.

---

## 6. Deep Dive: Every Module Explained

### 6.1 Entry Point — `analyzer/main.py`

**File**: [main.py](file:///c:/Users/Mridul/Desktop/supply-chain-analyzer/analyzer/main.py)
**Lines**: 180 &nbsp;|&nbsp; **Role**: Orchestrator / CLI interface

This is the brain of the application. The `main()` function is what runs when you type `scan-deps` in your terminal (thanks to the `entry_points` in `setup.py`). It does three things in sequence:

#### Phase 1 — Parsing (lines 36–73)
1. Reads the `-f` / `--file` argument to get the dependency file path.
2. Sets the `ecosystem` variable: `.txt` → `"python"`, `.json` → `"npm"`. This is later passed to the typosquatting scanner so it checks against the correct package list.
3. Checks the file extension: `.txt` → use `PythonParser`, `.json` → use `NpmParser`.
4. Calls `parser.parse()` which returns a list of dictionaries like:
   ```python
   [{"name": "requests", "version": "2.25.1"}, ...]
   ```
5. For npm projects, it also checks for a `node_modules/` directory next to `package.json` and calls `get_transitive_dependencies()` to scan indirect dependencies too.

#### Phase 1.5 — Dependency Graph (lines 76–94)
If `--graph` is passed:
1. Creates a `DependencyGraph` instance with the filename as the project name.
2. Calls `build_from_dependencies(deps, ecosystem)` which expands transitive deps from `known_deps.json`.
3. Prints the ASCII dependency tree via `render_tree(max_depth=args.graph_depth)`.
4. Prints the bordered stats box via `render_stats_box()`.
5. Serializes the full graph into the JSON report via `json_reporter.add_dependency_graph(graph.to_dict())`.

#### Phase 2 — Scanning (lines 96–165)
1. **Typosquatting scan** (unless `--no-typo`): Passes the dependency list and `ecosystem` to `TyposquattingScanner.scan()`. Alerts are printed with severity, technique, and confidence level. CRITICAL-severity findings (e.g., homoglyph attacks) use red `print_danger()`, others use yellow `print_warning()`.
2. **Vulnerability scan** (unless `--no-vuln`): Passes the dependency list to `VulnerabilityScanner.scan()`.
3. **Secret scan** (if `--scan-secrets`): Scans either the dependency file or an entire directory.
4. **Git history scan** (if `--scan-git`): Scans the last 50 Git commits for accidentally committed secrets.

#### Phase 3 — Reporting (lines 167–180)
1. Adds remediation recommendations based on what was found.
2. Saves the full structured report to a JSON file.
3. Prints a human-readable summary to the terminal.

---

### 6.2 Parsers — Reading Dependency Files

#### `PythonParser` — [python_parser.py](file:///c:/Users/Mridul/Desktop/supply-chain-analyzer/analyzer/parsers/python_parser.py)
**Lines**: 26 &nbsp;|&nbsp; **Role**: Parse `requirements.txt`

How it works:
1. Opens the file and reads it line by line.
2. Skips empty lines and comment lines (starting with `#`).
3. Uses a regex to extract the package name and version specifier:
   ```
   ^([a-zA-Z0-9\-_]+)(?:[=<>~]+(.*))?
   ```
   - Group 1 captures the package name (e.g., `requests`)
   - Group 2 captures the version (e.g., `2.25.1`). If no version is specified, it defaults to `"latest"`.
4. Returns a list of `{"name": "...", "version": "..."}` dictionaries.

**Example**: For the line `requests==2.25.1`, it produces `{"name": "requests", "version": "2.25.1"}`.

---

#### `NpmParser` — [npm_parser.py](file:///c:/Users/Mridul/Desktop/supply-chain-analyzer/analyzer/parsers/npm_parser.py)
**Lines**: 68 &nbsp;|&nbsp; **Role**: Parse `package.json` + scan `node_modules/`

The `parse()` method:
1. Loads the JSON file with `json.load()`.
2. Iterates over **four** dependency sections: `dependencies`, `devDependencies`, `peerDependencies`, `optionalDependencies`.
3. For each package, it creates a richer dictionary:
   ```python
   {
       "name": "express",
       "version": "^4.17.1",
       "type": "dependencies",       # which section it came from
       "is_dev": False,               # True only for devDependencies
       "is_optional": False           # True only for optionalDependencies
   }
   ```

The `get_transitive_dependencies()` method:
1. Walks the `node_modules/` directory.
2. For each sub-folder that contains a `package.json`, it reads the actual installed version.
3. Tags these as `"type": "transitive"`.

This allows the tool to catch vulnerabilities not just in direct dependencies, but in the entire dependency tree.

---

### 6.3 Scanners — The Security Engines

#### `TyposquattingScanner` — [typosquatting.py](file:///c:/Users/Mridul/Desktop/supply-chain-analyzer/analyzer/scanners/typosquatting.py)
**Lines**: 341 &nbsp;|&nbsp; **Role**: Multi-technique typosquatting detector

The scanner uses **7 detection techniques** to catch different flavors of typosquatting attacks. Techniques are ordered from most specific to broadest, so precise labels (like `character_swap`) take priority over the generic Levenshtein catch-all.

**Initialization**:
- Loads `data/popular_packages.json` — an ecosystem-aware database of **145 popular packages** split into `python` (66), `npm` (70), and `shared` (9) lists.
- When an `ecosystem` parameter is passed (e.g., `"python"`), only the relevant packages are checked. Falls back to the combined list if no ecosystem is specified.

**Detection Techniques**:

| # | Technique | What It Catches | Example | Confidence | Severity |
|---|---|---|---|---|---|
| 1 | **Separator confusion** | Dash / underscore / dot mismatches | `python_dateutil` ↔ `python-dateutil` | HIGH | HIGH |
| 2 | **Character swap** | Adjacent characters swapped | `reqeusts` → `requests` | HIGH | HIGH |
| 3 | **Repeated character** | One character doubled or removed | `flaask` → `flask` | MEDIUM | MEDIUM |
| 4 | **Homoglyph substitution** | Visually similar character substitutions | `f1ask` → `flask` (`1` → `l`) | CRITICAL | CRITICAL |
| 5 | **Version suffix** | Popular name + trailing digit | `requests2` → `requests` | HIGH | HIGH |
| 6 | **Combosquatting** | Popular name embedded with short prefix/suffix | `requests-lib` → `requests` | LOW | MEDIUM |
| 7 | **Levenshtein distance** | Generic edit distance 1–2 (catch-all) | `requess` → `requests` | HIGH/MEDIUM | HIGH/MEDIUM |

**Homoglyph map**: The scanner maintains a mapping of visually similar characters (`0↔o`, `1↔l`, `3↔e`, `4↔a`, `5↔s`, `7↔t`, `8↔b`, `9↔g`) and multi-character substitutions (`rn→m`, `vv→w`, `cl→d`, `nn→m`). Input names are normalized through this map before comparison.

**Output**: Each alert includes the detection technique, confidence level, and severity:
```python
{
    "type": "TYPOSQUATTING",
    "package": "reqeusts",
    "similar_to": "requests",
    "technique": "character_swap",
    "confidence": "HIGH",
    "severity": "HIGH",
    "message": "Adjacent character swap: 'reqeusts' has characters swapped compared to 'requests'"
}
```

**Deduplication**: A `seen` set tracks `(package, similar_to)` pairs to avoid duplicate alerts when multiple techniques could match the same pair.

---

#### `VulnerabilityScanner` — [vulnerability.py](file:///c:/Users/Mridul/Desktop/supply-chain-analyzer/analyzer/scanners/vulnerability.py)
**Lines**: 194 &nbsp;|&nbsp; **Role**: Check packages against known CVE databases

This is the most complex scanner. It has a 3-tier lookup strategy:

**Tier 1 — Local Cache** (`vulnerability_cache.json`)
- Before making any network call, it checks if this package has already been looked up.
- The cache is a JSON file mapping package names to lists of vulnerabilities.
- This prevents hammering APIs on repeated scans.

**Tier 2 — GitHub Advisory API** (`query_github_advisory()`, lines 47–105)
- Makes a GraphQL POST request to `https://api.github.com/graphql`.
- Queries the `securityVulnerabilities` endpoint with `ecosystem: PIP`.
- Returns CVE IDs, severity levels, vulnerable version ranges, summaries, and descriptions.
- Results are cached locally after retrieval.

**Tier 3 — Mock Database** (lines 16–27)
- If the API returns nothing (e.g., no internet, rate-limited), the scanner falls back to a hardcoded dictionary of known vulnerabilities for `django`, `requests`, and `flask`.
- This ensures the tool still works offline for common packages.

**There's also a 4th method** — `query_nvd_database()` (lines 107–137):
- Queries NIST's National Vulnerability Database REST API.
- This is defined but currently used as a secondary fallback. The main flow goes: Cache → GitHub → Mock.

**Version Matching** (`check_version_vulnerable()`, lines 139–153):
- Uses the `packaging` library's `SpecifierSet` to perform PEP 440-compliant version comparison.
- For example, if a CVE says `affected_versions: "<3.2.13"` and your package version is `3.2.0`, it correctly determines that `3.2.0 ∈ <3.2.13` → **vulnerable**.

**Output**: A list of alert dictionaries:
```python
{
    "type": "VULNERABILITY",
    "package": "django",
    "version": "3.2.0",
    "cve": "CVE-2022-28346",
    "severity": "HIGH",
    "message": "SQL Injection in QuerySet.values()",
    "description": "..."
}
```

---

#### `SecretsScanner` — [secrets.py](file:///c:/Users/Mridul/Desktop/supply-chain-analyzer/analyzer/scanners/secrets.py)
**Lines**: 187 &nbsp;|&nbsp; **Role**: Find hardcoded credentials in code and Git history

The scanner uses **10 regex patterns** to detect different types of secrets:

| Secret Type | Pattern Looks For | Severity |
|---|---|---|
| `AWS_KEY` | `AKIA` followed by 16 alphanumeric chars | CRITICAL |
| `AWS_SECRET` | `aws_secret_access_key = '...'` (40 chars) | CRITICAL |
| `GITHUB_TOKEN` | `ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_` tokens (36–255 chars) | CRITICAL |
| `PRIVATE_KEY` | `-----BEGIN RSA PRIVATE KEY`, `-----BEGIN PGP PRIVATE KEY`, etc. | CRITICAL |
| `API_KEY` | `api_key = "..."` or `api-key: "..."` (32+ chars) | HIGH |
| `PASSWORD` | `password = "..."` (8+ chars) | HIGH |
| `DATABASE_URI` | `mysql://`, `postgres://`, `mongodb://` connection strings | HIGH |
| `SLACK_WEBHOOK` | `https://hooks.slack.com/services/T.../B.../...` | HIGH |
| `STRIPE_KEY` | `sk_test_...` or `sk_live_...` (20+ chars) | CRITICAL |
| `JWT_TOKEN` | `eyJ....eyJ....` (Base64-encoded JWT structure) | MEDIUM |

**Three scanning modes**:

1. **`scan_file(file_path)`** — Reads a single file, runs all 10 regex patterns, and records the line number of each match. Automatically excludes `.git/`, `node_modules/`, `.venv/`, and `__pycache__/` paths.

2. **`scan_directory(directory_path)`** — Recursively walks a directory tree. Only scans files with specific extensions: `.py`, `.js`, `.ts`, `.json`, `.yml`, `.yaml`, `.txt`, `.md`, `.env`, `.sh`. Also scans dotenv files (`.env`, `.env.local`, `.env.example`). Skips excluded directories.

3. **`scan_git_history(repo_path)`** — Uses `subprocess` to run `git log --pretty=%H` (get all commit hashes), then `git show <hash>` for each of the last 50 commits. Runs all 10 regex patterns against each commit's diff output. This catches secrets that were committed once and then deleted — they're still in Git history!

---

### 6.4 Reporters — Presenting the Results

#### `ConsoleReporter` — [console.py](file:///c:/Users/Mridul/Desktop/supply-chain-analyzer/analyzer/reporters/console.py)
**Lines**: 40 &nbsp;|&nbsp; **Role**: Color-coded terminal output

Uses the `colorama` library for cross-platform colored text. Provides these output methods:

| Method | Color | Prefix | Used For |
|---|---|---|---|
| `print_header(text)` | Cyan + Bold | `=== ... ===` | Section headers |
| `print_success(text)` | Green | `[+]` | Positive results (no issues found) |
| `print_warning(text)` | Yellow | `[!] WARNING:` | Typosquatting alerts |
| `print_danger(text)` | Red + Bold | `[!] ALERT:` | Vulnerabilities and secrets |
| `print_info(text)` | Blue | `[~]` | Informational messages |
| `print_stream(text)` | Cyan | `[~]` | Live progress updates (overwrites same line using `\r`) |
| `clear_stream()` | — | — | Clears the live progress line |

The `print_stream` / `clear_stream` pair creates a "live scanning" effect in the terminal — you see the currently scanned package name updating in real time on a single line.

---

#### `JsonReporter` — [json_report.py](file:///c:/Users/Mridul/Desktop/supply-chain-analyzer/analyzer/reporters/json_report.py)
**Lines**: 185 &nbsp;|&nbsp; **Role**: Structured JSON report generation + security scoring

This is the most feature-rich reporter. It manages a `report_data` dictionary with this structure:

```json
{
  "metadata": {
    "generated_at": "2026-05-24T17:00:00.000000",
    "version": "1.0.0",
    "security_score": 69
  },
  "summary": {
    "total_dependencies": 10,
    "vulnerabilities_found": 2,
    "typosquatting_alerts": 1,
    "secrets_found": 3,
    "total_issues": 6,
    "severity_breakdown": {
      "CRITICAL": 1,
      "HIGH": 3,
      "MEDIUM": 1,
      "LOW": 1
    }
  },
  "dependencies": [...],
  "dependency_graph": {
    "project_name": "example_requirements.txt",
    "statistics": { "total_packages": 28, "direct_dependencies": 10, ... },
    "nodes": { "flask": { "depends_on": ["werkzeug", ...], ... }, ... },
    "tree_visualization": "..."
  },
  "vulnerabilities": [...],
  "typosquatting": [...],
  "secrets": [...],
  "recommendations": [...]
}
```

**Key methods**:
- `add_dependencies()` — Stores parsed dependency list and counts them.
- `add_dependency_graph()` — Stores the serialized graph data (nodes, edges, statistics, tree visualization).
- `add_vulnerability_alerts()` — Adds each vulnerability and increments the severity breakdown counters.
- `add_typosquatting_alerts()` — Adds alerts; uses the per-alert `severity` field (CRITICAL / HIGH / MEDIUM / LOW) from the scanner instead of a hardcoded value.
- `add_secrets_alerts()` — Adds secrets (strips the matched value for safety); increments severity counters.
- `add_recommendation()` — Adds timestamped remediation advice.
- `generate_security_score()` — Calculates the 0–100 score (see [Section 9](#9-the-security-scoring-system)).
- `generate_report_text()` — Produces a human-readable text summary.
- `save_json()` — Writes the full report to disk.
- `print_summary()` — Prints the text report to the console.

---

## 7. Data Files

### `data/popular_packages.json`
An **ecosystem-aware JSON object** containing **145 deduplicated popular package names** organized into three lists:

| Key | Count | Description |
|---|---|---|
| `python` | 66 | Top PyPI packages (requests, numpy, pandas, django, flask, cryptography, boto3, etc.) |
| `npm` | 70 | Top npm packages (express, react, vue, lodash, axios, webpack, next, prisma, etc.) |
| `shared` | 9 | Cross-ecosystem packages (docker, kubernetes, terraform, ansible, grpc, etc.) |

The scanner merges `shared` into the relevant ecosystem list at runtime. When no ecosystem is specified, all 145 packages are checked. The old flat-array format is also supported for backward compatibility.

### `data/known_deps.json`
A **transitive dependency metadata file** mapping **~70 popular packages** (40 Python + 30 npm) to their known direct dependencies. This enables the dependency graph engine to expand a flat `requirements.txt` into a full dependency tree without needing a lock file or installed virtualenv.

Example entry:
```json
{
  "python": {
    "flask": ["werkzeug", "jinja2", "click", "itsdangerous", "markupsafe"],
    "requests": ["urllib3", "certifi", "charset-normalizer", "idna"],
    ...
  },
  "npm": {
    "express": ["body-parser", "cookie", "debug", "finalhandler", ...],
    ...
  }
}
```

Packages not in this file appear as leaf nodes in the graph (no known transitive deps).

### `data/example_requirements.txt`
A sample Python `requirements.txt` with 10 common packages (requests, django, flask, numpy, etc.) — useful for testing the tool without needing a real project.

### `data/example_package.json`
A sample npm `package.json` with dependencies across all four sections (`dependencies`, `devDependencies`, `peerDependencies`, `optionalDependencies`) — demonstrates the full parsing capability.

### `vulnerability_cache.json`
A runtime-generated file that caches API responses from the GitHub Advisory and NVD APIs. Prevents redundant network calls on repeated scans. Initially populated with empty arrays for the tool's own dependencies (python-levenshtein, colorama, requests, packaging).

### `supply_chain_report.json`
The output from the last scan run. Contains the full structured report with metadata, summaries, detailed findings, and recommendations.

---

## 8. How the 3-Phase Pipeline Works (End-to-End Data Flow)

Here's what happens step-by-step when you run a typical command like:

```bash
scan-deps -f requirements.txt --scan-secrets -d . -o report.json
```

```
Step 1:  argparse reads CLI args
            │
            ▼
Step 2:  File extension check: .txt → PythonParser
            │
            ▼
Step 3:  PythonParser.parse() reads requirements.txt line by line
         Returns: [{"name": "requests", "version": "2.25.1"}, ...]
            │
            ▼
Step 4:  JsonReporter.add_dependencies(deps)  ← stores for final report
            │
            ▼
Step 4.5 (if --graph):  DependencyGraph:
         a. Load known transitive deps from known_deps.json
         b. Register all direct deps as graph nodes
         c. BFS-expand transitive deps from metadata
         d. Compute depths via BFS from root nodes
         e. Render ASCII tree + bordered stats box to terminal
         f. Serialize graph into JSON report
            │
            ▼
Step 5:  TyposquattingScanner (ecosystem-aware, e.g. 'python'):
         For each dep, run 7 detection techniques against 75 popular names:
           a. Separator confusion (dash/underscore/dot normalization)
           b. Character swap (adjacent transposition)
           c. Repeated character (doubled letter)
           d. Homoglyph substitution (visually similar chars: 1→l, 0→o)
           e. Version suffix squatting (popular_name + digit)
           f. Combosquatting (popular name embedded with short affix)
           g. Levenshtein distance 1–2 (catch-all)
         First matching technique wins → alert with technique, confidence, severity
            │
            ▼
Step 6:  VulnerabilityScanner:
         For each dep:
           a. Check local cache (vulnerability_cache.json)
           b. If not cached → call GitHub Advisory API
           c. If API returns nothing → check mock database
           d. For each known vuln, test: is this version in affected range?
           e. If yes → alert with CVE, severity, description
            │
            ▼
Step 7:  SecretsScanner:
         Walk all files in directory "."
         For each file with supported extension:
           Run 10 regex patterns → extract matches with line numbers
            │
            ▼
Step 8:  Generate remediation recommendations based on what was found
            │
            ▼
Step 9:  Calculate security score (100 minus severity-weighted deductions)
            │
            ▼
Step 10: Save JSON report to report.json
         Print human-readable summary to terminal
```

---

## 9. The Security Scoring System

The `JsonReporter.generate_security_score()` method computes a score from **0 to 100**, starting at a perfect 100 and deducting points for each issue found:

| Severity | Points Deducted Per Issue | Typical Triggers |
|---|---|---|
| **CRITICAL** | **-15** | AWS keys, private keys, Stripe live keys, GitHub tokens, homoglyph typosquatting |
| **HIGH** | **-8** | CVEs with CVSS ≥7, most typosquatting techniques (Levenshtein, separator, swap, version-suffix), passwords, database URIs |
| **MEDIUM** | **-3** | Moderate CVEs, JWT tokens, generic secrets, repeated-char typosquatting, combosquatting |
| **LOW** | **-1** | Informational findings, combosquatting (low-confidence) |

**Formula**:
```
score = max(0, 100 - (CRITICAL × 15) - (HIGH × 8) - (MEDIUM × 3) - (LOW × 1))
```

**Examples**:
- **No issues**: Score = 100 ✅
- **1 CRITICAL + 2 HIGH**: Score = 100 - 15 - 16 = **69**
- **3 CRITICAL + 5 HIGH + 2 MEDIUM**: Score = 100 - 45 - 40 - 6 = **9** 🔴
- **10+ CRITICAL**: Score = **0** (clamped, cannot go negative)

---

## 10. CLI Reference & Usage Examples

### Installation

```bash
pip install -r requirements.txt   # Install dependencies
pip install -e .                   # Install package in editable mode (creates `scan-deps` command)
```

### All CLI Flags

| Flag | Long Form | Argument | Description |
|---|---|---|---|
| `-f` | `--file` | `PATH` | Path to dependency file (`requirements.txt` or `package.json`) |
| `-d` | `--directory` | `PATH` | Directory to scan for secrets |
| `-o` | `--output` | `PATH` | Output JSON report path (default: `supply_chain_report.json`) |
| — | `--scan-secrets` | — | Enable secret scanning |
| — | `--scan-git` | — | Scan Git history for secrets |
| — | `--no-vuln` | — | Skip vulnerability scanning |
| — | `--no-typo` | — | Skip typosquatting scanning |
| — | `--graph` | — | Show dependency graph (ASCII tree + stats box) |
| — | `--graph-depth` | `INT` | Max depth for graph tree rendering (default: unlimited) |

### Usage Examples

```bash
# Basic Python project scan
scan-deps -f requirements.txt

# Scan npm project
scan-deps -f package.json

# Full scan with secrets and Git history
scan-deps -f requirements.txt --scan-secrets -d . --scan-git

# Scan with custom output path
scan-deps -f requirements.txt -o my_security_report.json

# Skip typosquatting, only check vulns
scan-deps -f requirements.txt --no-typo

# Skip vulns, only check typosquatting
scan-deps -f requirements.txt --no-vuln

# Scan a directory for secrets only (no dependency file needed)
scan-deps -d ./src --scan-secrets

# Show dependency graph (ASCII tree + stats box)
scan-deps -f requirements.txt --graph --no-vuln --no-typo

# Dependency graph with depth limit (collapse deep subtrees)
scan-deps -f package.json --graph --graph-depth 1

# Use the example data files
scan-deps -f data/example_requirements.txt --scan-secrets -d . -o example_report.json
```

---

## 11. Tests

**File**: [test_parsers.py](file:///c:/Users/Mridul/Desktop/supply-chain-analyzer/tests/test_parsers.py) &nbsp;|&nbsp; **Lines**: 270

The test suite uses Python's built-in `unittest` framework and covers **6 test classes** with **22 total tests**:

| Test Class | # Tests | What It Tests | Key Assertions |
|---|---|---|---|
| `TestPythonParser` | 1 | Parses a temp `requirements.txt` with 3 deps + comment | Correct count (3), correct name/version extraction |
| `TestNpmParser` | 1 | Parses a temp `package.json` with deps + devDeps | Correct count (3), `express` is present, dev dep is flagged |
| `TestTyposquattingScanner` | **9** | Tests all 7 detection techniques + false-positive guard | See breakdown below |
| `TestDependencyGraph` | **8** | Graph building, stats, cycles, tree rendering, depth | See breakdown below |
| `TestSecretsScanner` | 1 | Scans a temp file containing a password and Stripe key | At least 1 secret is found |
| `TestJsonReporter` | 1 | Creates report with 2 deps + 1 vulnerability | JSON file exists, correct counts in summary |

**Typosquatting test breakdown** (9 tests):

| Test | Input | Expected Technique |
|---|---|---|
| `test_levenshtein_distance_1` | `"requess"` | `levenshtein_distance_1` or `_2` |
| `test_levenshtein_distance_2` | `"numpyy"` | `levenshtein_distance_2` |
| `test_separator_confusion` | `"python_dateutil"` | `separator_confusion` |
| `test_character_swap` | `"reqeusts"` | `character_swap` |
| `test_repeated_character` | `"flaask"` | `repeated_character` |
| `test_homoglyph` | `"f1ask"` | `homoglyph` |
| `test_version_suffix` | `"requests2"` | `version_suffix` |
| `test_combosquatting` | `"requests-lib"` | `combosquatting` |
| `test_no_alert_for_exact_match` | `"requests"` | No alert (0 results) |

**Dependency graph test breakdown** (8 tests):

| Test | What It Verifies |
|---|---|
| `test_build_python_graph` | Flask gains transitive deps (werkzeug, jinja2, etc.) from known_deps.json |
| `test_build_npm_graph` | Express gains 30+ transitive deps |
| `test_unknown_package_leaf` | Unknown packages appear as leaf nodes with no children |
| `test_statistics` | Direct/transitive counts add up, max depth ≥ 1 |
| `test_no_cycles` | Normal graph has zero cycles |
| `test_detect_injected_cycle` | Manually injected a→b→c→a cycle is detected |
| `test_render_tree` | Tree output contains project name, direct deps, transitive deps |
| `test_stats_box_format` | Box has border chars and all expected labels |

**Run tests with**:
```bash
python -m pytest tests/ -v
```

> **Note**: `test_scanners.py` exists but is currently empty — a placeholder for future scanner-specific tests.

---

## 12. CI/CD Integration

The tool can be added to any CI/CD pipeline. Here's the provided GitHub Actions example:

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

This runs a full security scan on every push and pull request, generating a report artifact.

---

## 13. Key Design Decisions & Trade-offs

| Decision | Reasoning |
|---|---|
| **Pipeline architecture (Parse → Scan → Report)** | Clean separation of concerns. Each phase can be developed, tested, and swapped independently. |
| **Local vulnerability cache** | Reduces API calls and enables faster repeat scans. Trade-off: cache can become stale (no TTL/expiry mechanism). |
| **Mock vulnerability database** | Ensures the tool works offline for common packages. Trade-off: limited coverage (only 3 packages). |
| **7 detection techniques (not just Levenshtein)** | Levenshtein alone misses separator confusion, homoglyphs, and combosquatting. Multiple techniques catch more attack vectors while the priority ordering ensures the most specific label is shown first. |
| **Levenshtein as catch-all (last in priority)** | Runs after all specific techniques so labels like `character_swap` aren't masked by a generic `levenshtein_distance_2`. |
| **Ecosystem-aware package lists** | Scanning a Python project against npm-only packages (e.g., `express`) wastes time and can produce false positives. Separate lists reduce noise. |
| **Per-alert severity (not hardcoded HIGH)** | Homoglyph attacks (CRITICAL) are far more dangerous than combosquatting (MEDIUM). Variable severity gives accurate scoring. |
| **Known-deps metadata file for graph building** | `requirements.txt` is flat — it has no transitive dependency info. Rather than requiring a virtualenv or lock file, we ship `known_deps.json` with pre-mapped transitive deps for ~70 popular packages. This is the same approach `pipdeptree` uses offline. |
| **BFS for depth, DFS for cycles** | BFS naturally computes shortest-path depth from root. DFS with 3-color marking (white/gray/black) is the standard O(V+E) cycle detection algorithm. |
| **Depth-limited tree rendering** | `--graph-depth N` collapses deep subtrees to `... (N transitive deps)`, keeping output readable for projects with hundreds of transitive deps (like npm). |
| **UTF-8 stdout on Windows** | Windows terminals default to cp1252 which can't render box-drawing characters. The `sys.stdout.reconfigure(encoding='utf-8')` call at startup prevents UnicodeEncodeError crashes. |
| **Git history limited to 50 commits** | Balances thoroughness with performance. Scanning all commits in large repos could take minutes. |
| **10 regex patterns for secrets** | Covers the most common credential types. Trade-off: regex-based detection can have false positives (e.g., test fixtures) and false negatives (obfuscated secrets). |
| **All `__init__.py` files are empty** | Uses implicit namespace packages. Keeps the project simple — no circular import issues. |
| **`entry_points` in setup.py** | Creates the `scan-deps` command automatically on `pip install -e .`, so users don't need to remember `python -m analyzer.main`. |
| **Severity-weighted scoring** | A single number (0–100) is easier for teams to track and set thresholds on than raw vulnerability counts. |
| **Console + JSON dual reporting** | Humans read the terminal, CI pipelines consume the JSON. Both needs are met without extra tooling. |

---

## 14. Glossary of Terms

| Term | Definition |
|---|---|
| **CVE** | Common Vulnerabilities and Exposures — a unique identifier for a publicly known security vulnerability (e.g., CVE-2022-28346). |
| **SCA** | Software Composition Analysis — the practice of scanning third-party dependencies for known vulnerabilities. |
| **Typosquatting** | A supply chain attack where a malicious package is published with a name nearly identical to a popular one. |
| **Levenshtein Distance** | The minimum number of single-character edits (insert, delete, substitute) to transform one string into another. |
| **Homoglyph** | A character that looks visually identical or very similar to another (e.g., `1` and `l`, `0` and `o`). Used in homoglyph attacks to mimic package names. |
| **Combosquatting** | A variation of typosquatting where a popular name is embedded with a short prefix or suffix (e.g., `requests-lib`). |
| **Separator Confusion** | Exploiting the interchangeability of `-`, `_`, and `.` in package names (e.g., `python-dateutil` vs `python_dateutil`). |
| **PEP 440** | The Python standard for version numbering and specifiers (e.g., `>=3.2,<4.0`). |
| **NVD** | National Vulnerability Database — a US government repository of CVE data maintained by NIST. |
| **GitHub Advisory** | GitHub's security advisory database, queryable via GraphQL API. |
| **Transitive Dependency** | A dependency of your dependency. You didn't install it directly, but it's in your project through the dependency tree. |
| **Adjacency List** | A graph representation where each node stores a list of its neighbors. Used in the dependency graph to map packages to their dependencies. |
| **BFS (Breadth-First Search)** | A graph traversal algorithm that visits all neighbors at the current depth before moving deeper. Used for computing dependency depths. |
| **DFS (Depth-First Search)** | A graph traversal algorithm that explores as far as possible along each branch before backtracking. Used for cycle detection. |
| **Secret** | Any credential (API key, password, token, private key, connection string) that should not be in source code. |
| **CVSS** | Common Vulnerability Scoring System — a 0–10 scale for rating the severity of security vulnerabilities. |
| **GraphQL** | A query language for APIs. GitHub's Advisory API uses GraphQL instead of REST. |
| **Entry Point** | A mechanism in Python packaging that maps a command name (`scan-deps`) to a function (`analyzer.main:main`). |
