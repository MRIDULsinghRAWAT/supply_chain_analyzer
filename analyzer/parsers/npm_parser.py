import json
import os
import re

class NpmParser:
    def __init__(self, file_path):
        self.file_path = file_path

    def parse(self):
        """
        Parse package.json and extract dependencies
        Handles: dependencies, devDependencies, peerDependencies, optionalDependencies
        """
        dependencies = []
        
        if not os.path.exists(self.file_path):
            raise FileNotFoundError(f"File not found: {self.file_path}")

        try:
            with open(self.file_path, 'r') as file:
                package_json = json.load(file)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON format in {self.file_path}: {str(e)}")

        # Extract all dependency types
        dep_types = ['dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies']
        
        for dep_type in dep_types:
            if dep_type in package_json:
                for pkg_name, version_constraint in package_json[dep_type].items():
                    dependencies.append({
                        "name": pkg_name.lower(),
                        "version": version_constraint,
                        "type": dep_type,
                        "is_dev": dep_type == 'devDependencies',
                        "is_optional": dep_type == 'optionalDependencies'
                    })

        return dependencies

    def get_transitive_dependencies(self, node_modules_path):
        """
        Scan node_modules directory to extract transitive dependencies
        """
        transitive_deps = []
        
        if not os.path.exists(node_modules_path):
            return transitive_deps

        for package_name in os.listdir(node_modules_path):
            package_path = os.path.join(node_modules_path, package_name)
            package_json_path = os.path.join(package_path, 'package.json')
            
            if os.path.isdir(package_path) and os.path.exists(package_json_path):
                try:
                    with open(package_json_path, 'r') as f:
                        pkg_data = json.load(f)
                        version = pkg_data.get('version', 'unknown')
                        transitive_deps.append({
                            "name": package_name.lower(),
                            "version": version,
                            "type": "transitive"
                        })
                except (json.JSONDecodeError, IOError):
                    pass

        return transitive_deps
