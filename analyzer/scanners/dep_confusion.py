import os
import re
import requests

class DependencyConfusionScanner:
    def __init__(self, use_cache=True):
        self.cache_file = "dep_confusion_cache.json"
        self.cache = {}
        self.use_cache = use_cache
        self.load_cache()

    def load_cache(self):
        try:
            if self.use_cache and os.path.exists(self.cache_file):
                with open(self.cache_file, 'r', encoding='utf-8') as f:
                    import json
                    self.cache = json.load(f)
        except:
            self.cache = {}

    def save_cache(self):
        if self.use_cache:
            try:
                with open(self.cache_file, 'w', encoding='utf-8') as f:
                    import json
                    json.dump(self.cache, f)
            except:
                pass

    def check_public_registry(self, package_name, ecosystem):
        """Check if package exists in the public registry (returns True/False)"""
        cache_key = f"{ecosystem}:{package_name}"
        if cache_key in self.cache:
            return self.cache[cache_key]

        exists = False
        try:
            if ecosystem == "npm":
                url = f"https://registry.npmjs.org/{package_name}"
                response = requests.get(url, timeout=3)
                exists = (response.status_code == 200)
            elif ecosystem == "python":
                url = f"https://pypi.org/pypi/{package_name}/json"
                response = requests.get(url, timeout=3)
                exists = (response.status_code == 200)
            elif ecosystem == "ruby":
                url = f"https://rubygems.org/api/v1/gems/{package_name}.json"
                response = requests.get(url, timeout=3)
                exists = (response.status_code == 200)
        except:
            # Safe default to avoid false alarms on networking errors
            pass

        self.cache[cache_key] = exists
        self.save_cache()
        return exists

    def scan_configs(self, directory_path):
        """Scan directory for .npmrc, pip.conf and check registry configurations"""
        findings = []
        if not directory_path or not os.path.exists(directory_path):
            return findings

        # Check for .npmrc
        npmrc_path = os.path.join(directory_path, '.npmrc')
        if os.path.exists(npmrc_path):
            try:
                with open(npmrc_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                    
                # Look for custom registries
                registries = re.findall(r'(@[a-zA-Z0-9\-_]+):registry\s*=\s*(.+)', content)
                default_registry = re.search(r'^registry\s*=\s*(.+)', content, re.MULTILINE)
                
                if registries:
                    for scope, reg_url in registries:
                        findings.append({
                            "type": "DEP_CONFUSION_CONFIG",
                            "file": ".npmrc",
                            "severity": "LOW",
                            "message": f"Scoped registry configured for {scope}: {reg_url.strip()}. Ensure the scope is locked internally.",
                            "recommendation": "Review private scope configuration to prevent lookup leak."
                        })
                elif default_registry:
                    findings.append({
                        "type": "DEP_CONFUSION_CONFIG",
                        "file": ".npmrc",
                        "severity": "MEDIUM",
                        "message": f"Default npm registry overridden to: {default_registry.group(1).strip()}.",
                        "recommendation": "Ensure internal registry falls back securely without public leaking."
                    })
            except Exception as e:
                pass

        # Check for pip.conf
        pip_conf_paths = [
            os.path.join(directory_path, 'pip.conf'),
            os.path.join(directory_path, 'pip.ini')
        ]
        for pip_conf in pip_conf_paths:
            if os.path.exists(pip_conf):
                try:
                    with open(pip_conf, 'r', encoding='utf-8') as f:
                        content = f.read()
                    
                    # Look for extra-index-url
                    extra_urls = re.findall(r'extra-index-url\s*=\s*(.+)', content)
                    if extra_urls:
                        for url in extra_urls:
                            findings.append({
                                "type": "DEP_CONFUSION_CONFIG",
                                "file": os.path.basename(pip_conf),
                                "severity": "HIGH",
                                "message": f"Multiple index URLs configured using extra-index-url: {url.strip()}.",
                                "recommendation": "Using extra-index-url is vulnerable to dependency confusion. Use index-url with registry routing or pip-tools hashes instead."
                            })
                except:
                    pass

        return findings

    def scan_dependencies(self, dependencies, ecosystem):
        """Check if any internal/scoped dependencies are missing from public registry"""
        alerts = []
        for dep in dependencies:
            name = dep["name"]
            
            # Identify potential private packages:
            # - npm scoped packages (e.g. @company/package)
            # - packages matching company name conventions or custom patterns
            # - packages that do not exist on the public registry but are listed
            is_scoped = name.startswith("@")
            
            # Check public registry status
            exists_publicly = self.check_public_registry(name, ecosystem)
            
            if is_scoped and not exists_publicly:
                alerts.append({
                    "type": "DEPENDENCY_CONFUSION",
                    "package": name,
                    "severity": "CRITICAL",
                    "message": f"Private scoped package '{name}' is NOT registered on the public registry.",
                    "description": f"An attacker could claim '{name}' on the public registry, which could hijack your builds. Claim it as a placeholder package on public npm immediately."
                })
            elif not is_scoped and not exists_publicly and ecosystem in ("npm", "python", "ruby"):
                # If a dependency is listed in package.json/requirements.txt but not registered publicly,
                # it's likely a private package that hasn't been claimed publicly.
                alerts.append({
                    "type": "DEPENDENCY_CONFUSION",
                    "package": name,
                    "severity": "CRITICAL",
                    "message": f"Private dependency '{name}' is NOT registered on the public registry.",
                    "description": f"An attacker could register '{name}' publicly to execute a dependency confusion attack. Claim the namespace publicly to secure it."
                })

        return alerts
