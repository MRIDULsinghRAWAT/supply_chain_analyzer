import json
import os
import Levenshtein

class TyposquattingScanner:
    def __init__(self):
        # Load popular packages from data folder
        data_path = os.path.join(os.path.dirname(__file__), '../../data/popular_packages.json')
        with open(data_path, 'r') as f:
            self.popular_packages = json.load(f)

    def scan(self, dependencies):
        alerts = []
        for dep in dependencies:
            name = dep['name']
            if name not in self.popular_packages:
                for popular in self.popular_packages:
                    distance = Levenshtein.distance(name, popular)
                    if distance == 1 or distance == 2:
                        alerts.append({
                            "type": "TYPOSQUATTING",
                            "package": name,
                            "message": f"Looks similar to popular package '{popular}'"
                        })
        return alerts