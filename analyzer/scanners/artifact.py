import os
import re

class ArtifactScanner:
    def __init__(self):
        # Patterns to check in Dockerfile lines
        self.rules = [
            {
                "name": "UNPINNED_BASE_IMAGE",
                "pattern": r'^FROM\s+([a-zA-Z0-9\-_./]+)(?::latest)?(?:\s+|$)',
                "severity": "MEDIUM",
                "message": "Base image is unpinned or uses the 'latest' tag. This makes builds non-reproducible and risks pulling untested base changes."
            },
            {
                "name": "HARDCODED_ENV_SECRET",
                "pattern": r'^ENV\s+.*?(?:PASSWORD|SECRET|TOKEN|API_KEY|KEY|CREDENTIALS)\s*=\s*["\']?[a-zA-Z0-9\-_$]{8,}',
                "severity": "CRITICAL",
                "message": "Hardcoded secret detected in environment variables (ENV directive) in Dockerfile."
            },
            {
                "name": "UNSAFE_APT_GET",
                "pattern": r'apt-get\s+install(?!.*rm -rf /var/lib/apt/lists/\*)',
                "severity": "LOW",
                "message": "apt-get install should clean up /var/lib/apt/lists/* in the same RUN layer to keep the build layers small."
            },
            {
                "name": "UNSAFE_PIP_INSTALL",
                "pattern": r'pip\s+install(?!.*(?:-r|==|>=|<=|<|>))',
                "severity": "LOW",
                "message": "Running pip install without a requirements.txt or pinned version constraints is non-reproducible."
            }
        ]

    def scan_file(self, file_path):
        """Scan a single Dockerfile for security issues"""
        alerts = []
        if not os.path.exists(file_path):
            return alerts

        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                lines = content.splitlines()

            # Check rules line-by-line
            for line_idx, line in enumerate(lines, 1):
                clean_line = line.strip()
                if not clean_line or clean_line.startswith('#'):
                    continue

                for rule in self.rules:
                    if re.search(rule["pattern"], clean_line, re.IGNORECASE):
                        alerts.append({
                            "type": "ARTIFACT_RISK",
                            "file": file_path,
                            "line": line_idx,
                            "severity": rule["severity"],
                            "message": rule["message"],
                            "description": f"Directive: '{clean_line}'"
                        })

            # Check if USER instruction is present in the Dockerfile
            # Standard recommendation: do not run container as root
            has_user = any(line.strip().upper().startswith('USER') for line in lines if not line.strip().startswith('#'))
            if not has_user and len(lines) > 0:
                alerts.append({
                    "type": "ARTIFACT_RISK",
                    "file": file_path,
                    "severity": "MEDIUM",
                    "message": "Dockerfile does not contain a USER instruction. By default, container will run as root, increasing escalation risk.",
                    "description": "No 'USER' directive found. Container runs as root by default."
                })
        except Exception as e:
            pass

        return alerts

    def scan_directory(self, directory_path):
        """Recursively find and scan all Dockerfiles in a directory"""
        alerts = []
        if not directory_path or not os.path.exists(directory_path):
            return alerts

        for root, _, files in os.walk(directory_path):
            # Skip common noise dirs
            if any(x in root for x in ('.git', 'node_modules', '.venv', '__pycache__')):
                continue

            for file in files:
                # Matches Dockerfile, Dockerfile.dev, Dockerfile.prod, etc.
                if file.startswith('Dockerfile'):
                    alerts.extend(self.scan_file(os.path.join(root, file)))

        return alerts
