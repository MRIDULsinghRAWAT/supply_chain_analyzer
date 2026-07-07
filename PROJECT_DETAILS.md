# Project Details — Supply Chain Security Analyzer

This document explains how the entire project works, file by file, so you can understand the full codebase.

---

## What This Project Is

This is a Python CLI tool called `scan-deps` that checks your project's third-party dependencies for security risks. You give it a dependency file (like `requirements.txt` or `package.json`), and it:

1. Parses all the dependencies from that file
2. Builds a graph of how they depend on each other
3. Runs 8 different security checks against them
4. Generates a JSON report with findings, scores, and recommendations
5. Optionally shows a colored terminal dashboard

---

## How the Pipeline Works

The tool follows three phases:

```
PHASE 1: PARSE     -->     PHASE 1.5: GRAPH     -->     PHASE 2: SCAN     -->     PHASE 3: REPORT
(read manifest)         (build dependency tree)       (run 8 scanners)         (JSON + terminal)
```

**Phase 1 — Parsing:** Reads your manifest file and extracts a list of `{name, version}` pairs.

**Phase 1.5 — Graph:** Takes those dependencies, looks up their known sub-dependencies from `data/known_deps.json`, and builds a directed graph. Assigns depth levels (BFS), checks for cycles (DFS).

**Phase 2 — Scanning:** Runs each scanner on the dependency list. If a vulnerability is found in a transitive (indirect) dependency, the graph traces back to show which direct dependency pulled it in.

**Phase 3 — Reporting:** Collects all findings, computes a health score (0-100), generates recommendations, and writes everything to a JSON file.

---

## File-by-File Breakdown

### Entry Point

#### `analyzer/main.py`
This is where everything starts. The `main()` function:
- Sets up the CLI argument parser with all flags (`-f`, `-d`, `--scan-secrets`, `--graph`, `--dashboard`, `--no-cicd`, etc.)
- Detects the file type and calls the right parser
- Builds the dependency graph
- Runs each scanner in order
- Enriches transitive alerts with blast-radius paths
- Generates the final report

The `scan-deps` CLI command points directly to `main:main` (defined in `setup.py`).

---

### Parsers (`analyzer/parsers/`)

Each parser reads a specific manifest format and returns a list of dictionaries like `[{"name": "flask", "version": "2.3.2"}, ...]`.

#### `python_parser.py`
- Reads `requirements.txt` line by line
- Strips comments (`#`), blank lines, and inline options (`-i`, `--`)
- Splits on version operators (`==`, `>=`, `<=`, `~=`, `!=`)
- Returns `{name, version}` pairs

#### `npm_parser.py`
- Reads `package.json` as JSON
- Extracts from 4 sections: `dependencies`, `devDependencies`, `peerDependencies`, `optionalDependencies`
- Each dependency gets tagged with its type (e.g., `"dep_type": "devDependencies"`)
- Has a `get_transitive_dependencies()` method that walks `node_modules/` if it exists

#### `ruby_parser.py`
- Reads `Gemfile` line by line
- Uses regex to match `gem 'name', 'version'` patterns
- Handles single and double quotes, optional version constraints

#### `maven_parser.py`
- Reads `pom.xml` as XML using `xml.etree.ElementTree`
- Handles Maven XML namespaces dynamically (detects namespace from root tag)
- Resolves `<properties>` — if a version is `${some.property}`, it looks it up in the properties section
- Builds dependency names as `groupId:artifactId`
- Extracts `<scope>` (compile, test, provided, etc.)

---

### Scanners (`analyzer/scanners/`)

Each scanner takes a list of dependencies (and sometimes a directory path) and returns a list of alert dictionaries.

#### `vulnerability.py` — CVE Scanner (SCA)
- **Primary source:** GitHub Advisory GraphQL API. Sends a query with the package name and gets back CVE IDs, severity, and affected version ranges.
- **Fallback:** NVD (National Vulnerability Database) REST API at `services.nvd.nist.gov`.
- **Offline fallback:** A hardcoded mock database for common packages (django, requests, flask).
- **Caching:** Saves API responses to `vulnerability_cache.json` so repeated scans are instant.
- **Version matching:** Uses Python's `packaging.specifiers.SpecifierSet` to check if your installed version falls within the affected range. This handles complex version constraints like `>=3.2,<3.2.13`.

#### `typosquatting.py` — Package Name Mimicry
- Loads a list of popular/trusted packages from `data/popular_packages.json`
- For each dependency, runs 7 detection algorithms in priority order:
  1. **Levenshtein distance** — edit distance of 1-2 characters (uses `python-Levenshtein` library)
  2. **Homoglyph substitution** — checks for Unicode look-alikes (e.g., Cyrillic 'a' vs Latin 'a')
  3. **Character swap** — adjacent character transpositions
  4. **Repeated characters** — extra letter duplications
  5. **Combosquatting** — legitimate name with added prefix/suffix (e.g., `requests-secure`)
  6. **Separator confusion** — underscore vs hyphen vs dot variations
  7. **Version suffix** — appended numbers (e.g., `requests2`)
- Each match gets a confidence score. Results are sorted highest risk first.

#### `secrets.py` — Credential Detection
- Has 10+ regex patterns for:
  - AWS Access Key IDs (`AKIA...`)
  - AWS Secret Keys (40-char base64)
  - GitHub personal access tokens (`ghp_...`)
  - GitLab tokens (`glpat-...`)
  - Slack webhooks and bot tokens
  - Stripe keys (live and test)
  - Database URIs (`postgresql://`, `mongodb://`, `mysql://`)
  - Generic password assignments (`password = "..."`)
  - RSA/DSA/EC private key PEM headers
- `scan_directory()` — walks a directory tree recursively, skipping binary files, `.git/`, `tests/`, `test/`, `node_modules/`, and `__pycache__/`
- `scan_file()` — scans a single file
- `scan_git_history()` — runs `git log` + `git show` on the last 50 commits, applying the same patterns to diffs

#### `license.py` — License Compliance
- For each dependency, fetches license info from the appropriate registry:
  - Python: `https://pypi.org/pypi/{name}/json` (looks at `info.license` and classifiers)
  - npm: `https://registry.npmjs.org/{name}` (looks at `license` field)
  - Ruby: `https://rubygems.org/api/v1/gems/{name}.json`
- Maps the license string to a risk tier using a built-in dictionary:
  - **Permissive (LOW):** MIT, Apache-2.0, BSD-2-Clause, ISC, Unlicense
  - **Weak Copyleft (MEDIUM):** LGPL, MPL-2.0, EPL
  - **Strong Copyleft (HIGH):** GPL-2.0, GPL-3.0, AGPL-3.0
  - **Unknown:** No license detected
- Checks for conflicts: if the project has both copyleft and proprietary-licensed dependencies, it flags an incompatibility alert
- Caches all lookups in `license_cache.json`

#### `dep_confusion.py` — Dependency Confusion
- Scans `.npmrc` files for scoped registry mappings (e.g., `@company:registry=https://internal.npm/`)
- Scans `pip.conf` / `pip.ini` for `extra-index-url` entries pointing to private registries
- For scoped npm packages, checks if the scope's packages also exist on the public npm registry
- For Python packages with private indexes, checks if the name is registered on public PyPI
- If a private package name is available on the public registry, it flags a dependency confusion risk
- Caches results in `dep_confusion_cache.json`

#### `pipeline.py` — CI/CD Pipeline Audit
- Recursively searches for:
  - `.github/workflows/*.yml` (GitHub Actions)
  - `.gitlab-ci.yml` (GitLab CI)
  - `Jenkinsfile` (Jenkins)
- For GitHub Actions, checks each `uses:` statement:
  - Flags unpinned references (using `@main` or `@v3` instead of `@<commit-sha>`)
  - Flags `run:` steps with shell piping (`curl ... | bash`, `wget ... | sh`)
  - Flags environment variables that reference `secrets.*` in shell steps
- For GitLab CI, checks `script:` blocks for the same shell piping patterns
- For Jenkinsfile, looks for `sh` steps with curl/wget piping

#### `version_analyzer.py` — Outdated Version Check
- For each dependency, fetches the latest version from the upstream registry:
  - Python: PyPI JSON API
  - npm: npm registry API
  - Ruby: RubyGems API
- Compares the installed version against the latest. If they differ, generates an alert.
- Uses `packaging.version.parse()` for proper semantic version comparison.
- Caches results in `version_cache.json`


---

### Dependency Graph (`analyzer/graph/dependency_graph.py`)

This is the graph engine. Key concepts:

- **Adjacency list:** `adjacency[A]` = set of packages A depends on
- **Reverse adjacency:** `reverse[B]` = set of packages that depend on B
- **Metadata:** Each node stores version, type, depth level, and whether it's a direct dependency

**Building:**
- Takes parsed dependencies, looks them up in `data/known_deps.json` to find their sub-dependencies
- For npm, if `node_modules/` exists, it reads the actual installed packages for real transitive data

**Analysis:**
- `assign_depths()` — BFS from root, assigns depth level to each node (0 = direct, 1 = transitive, etc.)
- `detect_cycles()` — DFS with coloring to find circular dependencies
- `find_path_to(target)` — BFS from each direct dependency to find the shortest path to a target node. Used for blast-radius tracing.

**Visualization:**
- `render_tree()` — ASCII art dependency tree with indent lines
- `render_stats_box()` — Summary box showing total nodes, edges, max depth, cycles

---

### Reporters (`analyzer/reporters/`)

#### `console.py`
Simple colored terminal output using `colorama`:
- `print_header()` — cyan, bold section headers
- `print_success()` — green `[+]` messages
- `print_warning()` — yellow `[!]` warnings
- `print_danger()` — red, bold `[!]` alerts
- `print_info()` — blue `[~]` informational
- `print_stream()` — overwriting same-line progress updates

#### `json_report.py`
Builds the full structured report as a Python dictionary, then writes it to JSON:
- Tracks findings from every scanner
- Maintains severity counters (CRITICAL, HIGH, MEDIUM, LOW)
- Computes a health score: starts at 100, subtracts points per finding based on severity
- Stores remediation recommendations as a list
- `save_json()` — writes to disk
- `print_summary()` — prints a text summary to terminal

#### `dashboard.py`
Terminal dashboard using box-drawing characters and `colorama` colors:
- Header bar with project name
- Health score gauge (colored bar graph, green/yellow/red based on score)
- 4x2 grid of finding counts across all 8 categories
- Severity breakdown line
- Numbered list of recommended actions

---

### Data Files (`data/`)

#### `popular_packages.json`
List of well-known, trusted package names per ecosystem. Used by the typosquatting scanner as the reference set. Example: `{"python": ["requests", "flask", "django", ...], "npm": ["express", "lodash", ...]}`.

#### `known_deps.json`
Maps popular packages to their known sub-dependencies. Used by the dependency graph to build transitive relationships without needing the actual installed packages. Example: `{"python": {"flask": ["werkzeug", "jinja2", "click", ...], ...}}`.

#### `example_requirements.txt`
Sample Python `requirements.txt` file for demo/testing.

#### `example_package.json`
Sample Node.js `package.json` file for demo/testing.

---

### Tests (`tests/`)

Uses `pytest`. Three test files:

#### `test_parsers.py`
Tests Python and npm parsers, dependency graph building, and JSON reporter functionality.

#### `test_scanners.py`
Tests the core scanners: vulnerability scanner (including GraphQL API mocking, caching, and version matching), typosquatting detector, and secrets scanner.

#### `test_scanners_extended.py`
Tests Ruby and Maven parsers, dependency graph blast radius tracing, version staleness, license compliance, dependency confusion, CI/CD pipeline auditing, and CLI argument behaviors (like `--no-cicd`).

Total: 35 test cases.

---

### Configuration Files

#### `setup.py`
Standard setuptools config. Defines:
- Package name: `supply-chain-analyzer`
- Version: `1.1.0`
- Dependencies: `python-Levenshtein`, `colorama`, `requests`, `packaging`
- CLI entry point: `scan-deps` command maps to `analyzer.main:main`

#### `requirements.txt`
Same 4 dependencies listed in `setup.py`:
```
python-Levenshtein==0.25.1
colorama==0.4.6
requests==2.31.0
packaging==23.2
```

#### `.gitignore`
Ignores `__pycache__/`, cache JSON files, output reports, virtual environments, and build artifacts.

---

## How the Health Score Works

Starts at 100 and subtracts points for each finding:
- CRITICAL severity: -15 points each
- HIGH severity: -10 points each
- MEDIUM severity: -5 points each
- LOW severity: -2 points each

Minimum score is 0. The dashboard colors it:
- 80-100: Green ("SECURE")
- 50-79: Yellow ("WARNING")
- 0-49: Red ("VULNERABLE")

---

## How to Run

```bash
# Install
pip install -r requirements.txt
pip install -e .

# Run a scan
scan-deps -f data/example_requirements.txt --scan-secrets -d . --graph --dashboard

# Run tests
python -m pytest tests/ -v
```

---

## Technologies Used

| Library | Purpose |
|---|---|
| `requests` | HTTP calls to PyPI, npm, NVD, and GitHub APIs |
| `python-Levenshtein` | Fast edit distance computation for typosquatting |
| `colorama` | Cross-platform colored terminal output |
| `packaging` | PEP 440 version parsing and specifier matching |
| `xml.etree.ElementTree` | Maven pom.xml parsing (standard library) |
| `json` | JSON parsing and report generation (standard library) |
| `re` | Regex patterns for secrets detection (standard library) |
| `collections.deque` | BFS queue for graph traversal (standard library) |
| `argparse` | CLI argument parsing (standard library) |
| `pytest` | Test framework |
