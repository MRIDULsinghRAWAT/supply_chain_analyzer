import os
import xml.etree.ElementTree as ET
import re

class MavenParser:
    def __init__(self, file_path):
        self.file_path = file_path

    def parse(self):
        dependencies = []
        if not os.path.exists(self.file_path):
            raise FileNotFoundError(f"File not found: {self.file_path}")

        try:
            tree = ET.parse(self.file_path)
            root = tree.getroot()
        except ET.ParseError as e:
            raise ValueError(f"Invalid XML format in {self.file_path}: {str(e)}")

        # Extract namespace from root tag if present
        ns = ""
        if root.tag.startswith("{"):
            ns = root.tag.split("}")[0] + "}"

        # Parse properties to resolve version variables
        properties = {}
        properties_el = root.find(f".//{ns}properties")
        if properties_el is not None:
            for prop in properties_el:
                # Remove namespace from tag name
                tag_name = prop.tag.replace(ns, "") if ns else prop.tag
                properties[tag_name] = (prop.text or "").strip()

        # Helper function to resolve version variables
        def resolve_version(version_str):
            if not version_str:
                return "latest"
            
            # Match ${property_name}
            match = re.match(r"^\$\{(.+)\}$", version_str)
            if match:
                prop_name = match.group(1)
                return properties.get(prop_name, version_str)
            return version_str

        # Find dependencies in both <dependencies> and <dependencyManagement>
        dependency_elements = root.findall(f".//{ns}dependency")
        for dep_el in dependency_elements:
            group_id_el = dep_el.find(f"{ns}groupId")
            artifact_id_el = dep_el.find(f"{ns}artifactId")
            version_el = dep_el.find(f"{ns}version")
            scope_el = dep_el.find(f"{ns}scope")

            if group_id_el is not None and artifact_id_el is not None:
                group_id = (group_id_el.text or "").strip()
                artifact_id = (artifact_id_el.text or "").strip()
                version = (version_el.text or "").strip() if version_el is not None else "latest"
                scope = (scope_el.text or "compile").strip() if scope_el is not None else "compile"

                resolved_ver = resolve_version(version)
                pkg_name = f"{group_id}:{artifact_id}".lower()

                # Add to parsed dependencies list
                dependencies.append({
                    "name": pkg_name,
                    "version": resolved_ver,
                    "type": "dependencies",
                    "scope": scope,
                    "is_dev": scope in ("test", "provided")
                })

        return dependencies
