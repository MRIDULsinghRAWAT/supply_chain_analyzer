import re
import os

class PythonParser:
    def __init__(self, file_path):
        self.file_path = file_path

    def parse(self):
        dependencies = []
        if not os.path.exists(self.file_path):
            raise FileNotFoundError(f"File not found: {self.file_path}")

        with open(self.file_path, 'r') as file:
            for line in file:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                
                # Regex for package==version
                match = re.match(r'^([a-zA-Z0-9\-_]+)(?:[=<>~]+(.*))?', line)
                if match:
                    pkg_name = match.group(1).lower()
                    pkg_version = match.group(2) if match.group(2) else "latest"
                    dependencies.append({"name": pkg_name, "version": pkg_version})
                    
        return dependencies