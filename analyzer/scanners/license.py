import os
import json
import requests

class LicenseScanner:
    def __init__(self, use_cache=True):
        self.cache_file = "license_cache.json"
        self.license_cache = {}
        self.use_cache = use_cache
        self.load_cache()

        # Fallback database of popular packages' licenses (Python, npm, Ruby, Maven)
        self.mock_db = {
            "requests": "Apache-2.0",
            "django": "BSD-3-Clause",
            "flask": "BSD-3-Clause",
            "numpy": "BSD-3-Clause",
            "pandas": "BSD-3-Clause",
            "cryptography": "Apache-2.0",
            "gunicorn": "MIT",
            
            "express": "MIT",
            "react": "MIT",
            "vue": "MIT",
            "lodash": "MIT",
            "axios": "MIT",
            "chalk": "MIT",
            
            "rails": "MIT",
            "puma": "BSD-3-Clause",
            "sqlite3": "Public-Domain",
            "nokogiri": "MIT",
            
            "junit:junit": "EPL-2.0",
            "org.apache.commons:commons-lang3": "Apache-2.0",
            "org.springframework:spring-core": "Apache-2.0",
            "org.slf4j:slf4j-api": "MIT"
        }

    def load_cache(self):
        """Load license cache from file"""
        try:
            if self.use_cache and os.path.exists(self.cache_file):
                with open(self.cache_file, 'r', encoding='utf-8') as f:
                    self.license_cache = json.load(f)
        except:
            self.license_cache = {}

    def save_cache(self):
        """Save license cache to file"""
        if self.use_cache:
            try:
                with open(self.cache_file, 'w', encoding='utf-8') as f:
                    json.dump(self.license_cache, f)
            except:
                pass

    def get_license_from_api(self, name, ecosystem):
        """Query external package registry API to find package license"""
        # Return from cache if present
        cache_key = f"{ecosystem}:{name}"
        if cache_key in self.license_cache:
            return self.license_cache[cache_key]

        license_name = "Unknown"
        
        try:
            if ecosystem == "python":
                url = f"https://pypi.org/pypi/{name}/json"
                response = requests.get(url, timeout=3)
                if response.status_code == 200:
                    info = response.json().get("info", {})
                    license_name = info.get("license") or "Unknown"
                    if license_name == "Unknown" or not license_name.strip():
                        # Try parsing from classifiers
                        for classifier in info.get("classifiers", []):
                            if classifier.startswith("License ::"):
                                license_name = classifier.split("::")[-1].strip()
                                break
            elif ecosystem == "npm":
                url = f"https://registry.npmjs.org/{name}/latest"
                response = requests.get(url, timeout=3)
                if response.status_code == 200:
                    data = response.json()
                    lic = data.get("license")
                    if isinstance(lic, dict):
                        license_name = lic.get("type", "Unknown")
                    elif isinstance(lic, str):
                        license_name = lic
            elif ecosystem == "ruby":
                url = f"https://rubygems.org/api/v1/gems/{name}.json"
                response = requests.get(url, timeout=3)
                if response.status_code == 200:
                    licenses = response.json().get("licenses")
                    if licenses:
                        license_name = ", ".join(licenses)
            elif ecosystem == "maven":
                # For maven, name is group:artifact. Solr Search API does not return licenses,
                # but we can try parsing the POM from Maven Central for license details.
                # However, to be fast, we rely on the mock database or tag as Unknown.
                pass
        except:
            pass

        # Clean up license name
        if not license_name or license_name.lower() in ("unknown", "none", "null", ""):
            license_name = self.mock_db.get(name, self.mock_db.get(name.lower(), "Unknown"))

        # Cache the result
        self.license_cache[cache_key] = license_name
        self.save_cache()
        return license_name

    def classify_risk(self, license_str):
        """Classify a license string into a risk level (HIGH, MEDIUM, LOW)"""
        lic = (license_str or "").upper()
        
        # High Risk Copyleft
        if any(x in lic for x in ["GPL", "AGPL", "LGPL", "EPL", "MPL", "CDDL"]):
            return "HIGH", "Copyleft / Restrictive License"
        
        # Permissive Licenses (Low Risk)
        if any(x in lic for x in ["MIT", "APACHE", "BSD", "ISC", "PUBLIC", "UNLICENSE", "WTFPL"]):
            return "LOW", "Permissive License"
            
        # If it is Unknown/Proprietary
        if "PROPRIETARY" in lic or "COMMERCIAL" in lic:
            return "MEDIUM", "Proprietary / Commercial License"
            
        return "MEDIUM", "Unknown / Undefined License"

    def scan(self, dependencies, ecosystem=None, reporter=None):
        """Scan dependencies for licenses and detect risk levels and conflicts"""
        alerts = []
        licenses_found = {}

        for dep in dependencies:
            name = dep["name"]
            eco = dep.get("ecosystem", ecosystem or "python")
            
            if reporter:
                reporter.print_stream(f"Live Stream: Scanning license for '{name}'...")
                
            license_name = self.get_license_from_api(name, eco)
            risk, description = self.classify_risk(license_name)
            
            licenses_found[name] = {
                "license": license_name,
                "risk": risk,
                "description": description
            }
            
            if risk == "HIGH":
                alerts.append({
                    "type": "LICENSE_RISK",
                    "package": name,
                    "license": license_name,
                    "severity": "HIGH",
                    "message": f"Restrictive copyleft license '{license_name}' detected. This might require you to open-source your proprietary code.",
                    "description": description
                })

        # Conflict Detection
        # E.g., if there's both a copyleft license (HIGH risk) and a proprietary license (MEDIUM risk)
        has_copyleft = any(info["risk"] == "HIGH" for info in licenses_found.values())
        has_proprietary = any("commercial" in info["license"].lower() or "proprietary" in info["license"].lower() for info in licenses_found.values())
        
        if has_copyleft and has_proprietary:
            alerts.append({
                "type": "LICENSE_CONFLICT",
                "package": "project",
                "severity": "CRITICAL",
                "message": "License conflict detected: Project contains both restrictive copyleft (e.g. GPL/EPL) and proprietary/commercial dependencies.",
                "description": "Copyleft licenses require derivative works to be released under the same license, which directly conflicts with proprietary license terms."
            })

        if reporter:
            reporter.clear_stream()

        return alerts, licenses_found
