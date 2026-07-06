import re
import os

class RubyParser:
    def __init__(self, file_path):
        self.file_path = file_path

    def parse(self):
        dependencies = []
        if not os.path.exists(self.file_path):
            raise FileNotFoundError(f"File not found: {self.file_path}")

        with open(self.file_path, 'r', encoding='utf-8') as file:
            for line in file:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                
                # Check for lines starting with 'gem'
                if line.startswith('gem'):
                    # Regex to match gem 'name' or gem 'name', 'version'
                    # Supports single/double quotes, possible options, etc.
                    # gem 'rails', '~> 6.1.4'
                    # gem 'sqlite3'
                    match = re.match(r"^gem\s+['\"]([^'\"]+)['\"](?:\s*,\s*['\"]([^'\"]+)['\"])?", line)
                    if match:
                        pkg_name = match.group(1).lower()
                        pkg_version = match.group(2) if match.group(2) else "latest"
                        
                        dependencies.append({
                            "name": pkg_name,
                            "version": pkg_version,
                            "type": "dependencies"
                        })
        return dependencies
