import unittest
import os
import json
import tempfile
from analyzer.parsers.python_parser import PythonParser
from analyzer.parsers.npm_parser import NpmParser
from analyzer.scanners.typosquatting import TyposquattingScanner
from analyzer.scanners.vulnerability import VulnerabilityScanner
from analyzer.scanners.secrets import SecretsScanner
from analyzer.reporters.json_report import JsonReporter

class TestPythonParser(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
    
    def test_parse_requirements(self):
        # Create temporary requirements.txt
        req_file = os.path.join(self.temp_dir, "requirements.txt")
        with open(req_file, 'w') as f:
            f.write("requests==2.25.1\ndjango>=3.2\nflask\n# This is a comment\n")
        
        parser = PythonParser(req_file)
        deps = parser.parse()
        
        self.assertEqual(len(deps), 3)
        self.assertEqual(deps[0]['name'], 'requests')
        self.assertEqual(deps[0]['version'], '2.25.1')

class TestNpmParser(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
    
    def test_parse_package_json(self):
        # Create temporary package.json
        package_file = os.path.join(self.temp_dir, "package.json")
        package_data = {
            "name": "test-app",
            "version": "1.0.0",
            "dependencies": {
                "express": "^4.17.1",
                "axios": "~0.21.0"
            },
            "devDependencies": {
                "jest": "^27.0.0"
            }
        }
        with open(package_file, 'w') as f:
            json.dump(package_data, f)
        
        parser = NpmParser(package_file)
        deps = parser.parse()
        
        self.assertEqual(len(deps), 3)
        self.assertTrue(any(d['name'] == 'express' for d in deps))
        self.assertTrue(any(d['is_dev'] for d in deps))

class TestTyposquattingScanner(unittest.TestCase):
    def test_detect_typosquatting(self):
        scanner = TyposquattingScanner()
        
        # Test with typosquatted package
        deps = [{"name": "requess", "version": "1.0.0"}]  # Similar to "requests"
        alerts = scanner.scan(deps)
        
        self.assertTrue(len(alerts) > 0)
        self.assertEqual(alerts[0]['type'], 'TYPOSQUATTING')

class TestSecretsScanner(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
    
    def test_scan_for_secrets(self):
        scanner = SecretsScanner()
        
        # Create file with secrets
        test_file = os.path.join(self.temp_dir, "config.py")
        with open(test_file, 'w') as f:
            f.write("""
PASSWORD = "supersecret123"
api_key = "sk_test_4eC39HqLyjWDarht1234567890"
""")
        
        secrets = scanner.scan_file(test_file)
        
        # Should find at least one secret
        self.assertTrue(len(secrets) > 0)

class TestJsonReporter(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
    
    def test_generate_json_report(self):
        reporter = JsonReporter(os.path.join(self.temp_dir, "report.json"))
        
        # Add test data
        reporter.add_dependencies([
            {"name": "requests", "version": "2.25.1"},
            {"name": "django", "version": "3.2.0"}
        ])
        
        reporter.add_vulnerability_alerts([
            {
                "package": "django",
                "version": "3.2.0",
                "severity": "HIGH",
                "message": "CVE-2022-28346"
            }
        ])
        
        # Save and verify
        report_path = reporter.save_json()
        self.assertTrue(os.path.exists(report_path))
        
        with open(report_path, 'r') as f:
            data = json.load(f)
        
        self.assertEqual(data['summary']['total_dependencies'], 2)
        self.assertEqual(data['summary']['vulnerabilities_found'], 1)

if __name__ == '__main__':
    unittest.main()
