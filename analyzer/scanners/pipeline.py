import os
import re

class PipelineScanner:
    def __init__(self):
        # Patterns to search in files
        self.patterns = {
            "CURL_BASH": (
                r'(?:curl|wget)\s+[^\n|]+\|\s*(?:bash|sh)',
                "Suspicious command execution using 'curl | bash' or 'wget | sh'. This executes remote unverified code.",
                "HIGH"
            ),
            "UNPINNED_ACTION": (
                r'uses:\s*([a-zA-Z0-9\-_]+/[a-zA-Z0-9\-_]+)@(?!v?[0-9a-f]{40}\b)([a-zA-Z0-9\-_.]+)',
                "CI/CD Action is not pinned to a specific commit SHA (uses mutable tag/branch). An attacker could hijack the reference.",
                "MEDIUM"
            ),
            "SECRET_EXFILTRATION": (
                r'(?:curl|wget|nc|bash -i).*?(?:\$AWS_|\$GITHUB_|\$SLACK_|\$STRIPE_|\$API_|\$TOKEN|\$SECRET|\$PASSWORD|\$KEY|env\b)',
                "Potential credential exfiltration pattern detected: sending sensitive env variables/keys over network.",
                "CRITICAL"
            ),
            "HARDCODED_ENV_TOKEN": (
                r'(?:TOKEN|KEY|PASSWORD|SECRET|PASSWORD)\s*:\s*["\']([^$\n"\']{8,})["\']',
                "Hardcoded secret/token value detected in pipeline environment definition.",
                "CRITICAL"
            )
        }

    def scan_file(self, file_path):
        """Scan a single pipeline file for vulnerabilities"""
        alerts = []
        if not os.path.exists(file_path):
            return alerts

        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                for line_idx, line in enumerate(f, 1):
                    # Check each pattern
                    for pat_name, (pattern, msg, severity) in self.patterns.items():
                        match = re.search(pattern, line)
                        if match:
                            detail = f"Match: '{match.group(0).strip()}'"
                            alerts.append({
                                "type": "PIPELINE_RISK",
                                "file": file_path,
                                "line": line_idx,
                                "pattern_name": pat_name,
                                "severity": severity,
                                "message": msg,
                                "description": detail
                            })
        except:
            pass

        return alerts

    def scan_directory(self, directory_path):
        """Recursively search for CI/CD pipeline files and scan them"""
        alerts = []
        if not directory_path or not os.path.exists(directory_path):
            return alerts

        pipeline_dirs = [
            ".github/workflows",
            ".gitlab",
            ".circleci",
            "ci"
        ]
        
        pipeline_files = [
            ".gitlab-ci.yml",
            ".gitlab-ci.yaml",
            "Jenkinsfile",
            "travis.yml",
            "appveyor.yml"
        ]

        # Scan explicitly defined directories
        for p_dir in pipeline_dirs:
            full_dir = os.path.join(directory_path, p_dir)
            if os.path.exists(full_dir) and os.path.isdir(full_dir):
                for root, _, files in os.walk(full_dir):
                    for file in files:
                        if file.endswith(('.yml', '.yaml')):
                            alerts.extend(self.scan_file(os.path.join(root, file)))

        # Scan explicitly defined files in the root
        for p_file in pipeline_files:
            full_path = os.path.join(directory_path, p_file)
            if os.path.exists(full_path) and os.path.isfile(full_path):
                alerts.extend(self.scan_file(full_path))

        return alerts
