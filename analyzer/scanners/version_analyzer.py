import os
import json
import requests
import re
from packaging import version as pkg_version

class VersionAnalyzer:
    def __init__(self, use_cache=True):
        self.cache_file = "version_cache.json"
        self.version_cache = {}
        self.use_cache = use_cache
        self.load_cache()

        # Offline mock database of latest popular versions
        self.mock_db = {
            "django": "5.0.6",
            "requests": "2.32.3",
            "flask": "3.0.3",
            "numpy": "1.26.4",
            "pandas": "2.2.2",
            
            "express": "4.19.2",
            "react": "18.3.1",
            "vue": "3.4.27",
            "lodash": "4.17.21",
            
            "rails": "7.1.3",
            "puma": "6.4.2",
            "sqlite3": "1.7.3",
            
            "junit:junit": "4.13.2",
            "org.apache.commons:commons-lang3": "3.14.0",
            "org.springframework:spring-core": "6.1.8"
        }

    def load_cache(self):
        try:
            if self.use_cache and os.path.exists(self.cache_file):
                with open(self.cache_file, 'r', encoding='utf-8') as f:
                    self.version_cache = json.load(f)
        except:
            self.version_cache = {}

    def save_cache(self):
        if self.use_cache:
            try:
                with open(self.cache_file, 'w', encoding='utf-8') as f:
                    json.dump(self.version_cache, f)
            except:
                pass

    def get_latest_version(self, name, ecosystem):
        """Query registry APIs for the latest released version of a package"""
        cache_key = f"{ecosystem}:{name}"
        if cache_key in self.version_cache:
            return self.version_cache[cache_key]

        latest = "0.0.0"
        try:
            if ecosystem == "python":
                url = f"https://pypi.org/pypi/{name}/json"
                response = requests.get(url, timeout=3)
                if response.status_code == 200:
                    latest = response.json().get("info", {}).get("version", "0.0.0")
            elif ecosystem == "npm":
                url = f"https://registry.npmjs.org/{name}/latest"
                response = requests.get(url, timeout=3)
                if response.status_code == 200:
                    latest = response.json().get("version", "0.0.0")
            elif ecosystem == "ruby":
                url = f"https://rubygems.org/api/v1/gems/{name}.json"
                response = requests.get(url, timeout=3)
                if response.status_code == 200:
                    latest = response.json().get("version", "0.0.0")
            elif ecosystem == "maven":
                if ":" in name:
                    group, artifact = name.split(":")
                else:
                    group, artifact = name, name
                url = f"https://search.maven.org/solrsearch/select?q=g:\"{group}\"+AND+a:\"{artifact}\"&rows=1&wt=json"
                response = requests.get(url, timeout=3)
                if response.status_code == 200:
                    docs = response.json().get("response", {}).get("docs", [])
                    if docs:
                        latest = docs[0].get("latestVersion", "0.0.0")
        except:
            pass

        # Fallback to mock db if we got 0.0.0 or failed
        if latest == "0.0.0" or not latest:
            latest = self.mock_db.get(name, self.mock_db.get(name.lower(), "0.0.0"))

        self.version_cache[cache_key] = latest
        self.save_cache()
        return latest

    def clean_version(self, version_str):
        """Extract a clean base version from constraint characters"""
        if not version_str or version_str.lower() in ("latest", "transitive", "unknown"):
            return "0.0.0"
        # Match digits/periods/alphanumeric in version (e.g. >=1.2.3 -> 1.2.3)
        match = re.search(r'([0-9]+(?:\.[0-9]+)*(?:\.[0-9a-zA-Z\-]+)?)', version_str)
        if match:
            return match.group(1)
        return "0.0.0"

    def scan(self, dependencies, ecosystem=None, reporter=None):
        """Scan dependencies to see if they are outdated"""
        alerts = []
        
        for dep in dependencies:
            name = dep["name"]
            raw_version = dep["version"]
            eco = dep.get("ecosystem", ecosystem or "python")

            if reporter:
                reporter.print_stream(f"Live Stream: Checking version constraint for '{name}'...")

            installed = self.clean_version(raw_version)
            latest = self.get_latest_version(name, eco)

            if installed == "0.0.0" or latest == "0.0.0":
                continue

            try:
                if pkg_version.parse(installed) < pkg_version.parse(latest):
                    alerts.append({
                        "type": "OUTDATED_PACKAGE",
                        "package": name,
                        "installed_version": installed,
                        "latest_version": latest,
                        "severity": "LOW",
                        "message": f"Package '{name}' is outdated (installed: {installed}, latest: {latest}). Consider upgrading."
                    })
            except:
                pass

        if reporter:
            reporter.clear_stream()

        return alerts
