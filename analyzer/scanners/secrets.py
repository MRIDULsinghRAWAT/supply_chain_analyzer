import re
import os
import subprocess

class SecretsScanner:
    def __init__(self):
        # Define patterns for common secrets
        self.secret_patterns = {
            "AWS_KEY": {
                "pattern": r"AKIA[0-9A-Z]{16}",
                "severity": "CRITICAL",
                "description": "AWS Access Key ID"
            },
            "AWS_SECRET": {
                "pattern": r"aws_secret_access_key\s*=\s*['\"]([A-Za-z0-9/+=]{40})['\"]",
                "severity": "CRITICAL",
                "description": "AWS Secret Access Key"
            },
            "GITHUB_TOKEN": {
                "pattern": r"gh[pousr]{1}_[A-Za-z0-9_]{36,255}",
                "severity": "CRITICAL",
                "description": "GitHub Personal Access Token"
            },
            "PRIVATE_KEY": {
                "pattern": r"-----BEGIN (?:RSA|DSA|EC|OPENSSH|PGP) PRIVATE KEY",
                "severity": "CRITICAL",
                "description": "Private Key File"
            },
            "API_KEY": {
                "pattern": r"api[_-]?key['\"]?\s*[:=]\s*['\"]?([a-zA-Z0-9\-_]{32,})['\"]?",
                "severity": "HIGH",
                "description": "Generic API Key"
            },
            "PASSWORD": {
                "pattern": r"password['\"]?\s*[:=]\s*['\"]([^'\"]{8,})['\"]",
                "severity": "HIGH",
                "description": "Password in code"
            },
            "DATABASE_URI": {
                "pattern": r"(mysql|postgres|mongodb)://[a-zA-Z0-9:@._/]+",
                "severity": "HIGH",
                "description": "Database Connection String"
            },
            "SLACK_WEBHOOK": {
                "pattern": r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+",
                "severity": "HIGH",
                "description": "Slack Webhook URL"
            },
            "STRIPE_KEY": {
                "pattern": r"(sk_test_|sk_live_)[A-Za-z0-9]{20,}",
                "severity": "CRITICAL",
                "description": "Stripe API Key"
            },
            "JWT_TOKEN": {
                "pattern": r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
                "severity": "MEDIUM",
                "description": "JWT Token"
            }
        }

    def scan_file(self, file_path, exclude_patterns=None):
        """
        Scan individual file for secrets
        """
        secrets_found = []
        
        if exclude_patterns is None:
            exclude_patterns = ['.git', 'node_modules', '.venv', '__pycache__']

        # Check if file should be excluded
        for pattern in exclude_patterns:
            if pattern in file_path:
                return secrets_found

        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                
                for secret_type, pattern_info in self.secret_patterns.items():
                    matches = re.finditer(pattern_info['pattern'], content, re.IGNORECASE)
                    for match in matches:
                        # Get line number
                        line_num = content[:match.start()].count('\n') + 1
                        secrets_found.append({
                            "type": secret_type,
                            "file": file_path,
                            "line": line_num,
                            "severity": pattern_info['severity'],
                            "description": pattern_info['description'],
                            "matched_value": match.group(0)[:50] + "..." if len(match.group(0)) > 50 else match.group(0)
                        })
        except (IOError, UnicodeDecodeError):
            pass

        return secrets_found

    def scan_directory(self, directory_path, extensions=None):
        """
        Recursively scan directory for secrets
        """
        if extensions is None:
            extensions = ['.py', '.js', '.ts', '.json', '.yml', '.yaml', '.txt', '.md', '.env', '.sh']

        secrets_found = []
        
        for root, dirs, files in os.walk(directory_path):
            # Skip common excluded directories
            dirs[:] = [d for d in dirs if d not in ['.git', 'node_modules', '.venv', '__pycache__', '.env']]
            
            for file in files:
                file_path = os.path.join(root, file)
                file_ext = os.path.splitext(file)[1]
                
                # Check if file extension is in our list or if it's a common config file
                if file_ext in extensions or file in ['.env', '.env.local', '.env.example']:
                    secrets = self.scan_file(file_path)
                    secrets_found.extend(secrets)

        return secrets_found

    def scan_git_history(self, repo_path):
        """
        Scan git commit history for secrets (requires git to be installed)
        """
        secrets_found = []
        
        try:
            # Check if directory is a git repo
            if not os.path.exists(os.path.join(repo_path, '.git')):
                return secrets_found

            # Get all commits
            result = subprocess.run(
                ['git', 'log', '--pretty=%H'],
                cwd=repo_path,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode != 0:
                return secrets_found

            commits = result.stdout.strip().split('\n')
            
            for commit in commits[:50]:  # Limit to recent 50 commits for performance
                try:
                    show_result = subprocess.run(
                        ['git', 'show', commit],
                        cwd=repo_path,
                        capture_output=True,
                        text=True,
                        timeout=10
                    )
                    
                    if show_result.returncode == 0:
                        content = show_result.stdout
                        
                        for secret_type, pattern_info in self.secret_patterns.items():
                            matches = re.finditer(pattern_info['pattern'], content, re.IGNORECASE)
                            for match in matches:
                                secrets_found.append({
                                    "type": secret_type,
                                    "file": "git_history",
                                    "commit": commit[:8],
                                    "severity": pattern_info['severity'],
                                    "description": pattern_info['description'],
                                    "matched_value": match.group(0)[:30] + "..." if len(match.group(0)) > 30 else match.group(0)
                                })
                except subprocess.TimeoutExpired:
                    continue
                    
        except (FileNotFoundError, subprocess.SubprocessError):
            # git not installed or not a git repo
            pass

        return secrets_found
