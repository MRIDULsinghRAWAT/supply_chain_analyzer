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
from analyzer.graph.dependency_graph import DependencyGraph

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
    def setUp(self):
        self.scanner = TyposquattingScanner()

    # --- Levenshtein distance -----------------------------------------------
    def test_levenshtein_distance_1(self):
        """Edit distance 1: 'requess' → 'requests' (missing a 't')."""
        deps = [{"name": "requess", "version": "1.0.0"}]
        alerts = self.scanner.scan(deps)
        self.assertTrue(len(alerts) > 0)
        matching = [a for a in alerts if a['similar_to'] == 'requests']
        self.assertTrue(len(matching) > 0)
        self.assertEqual(matching[0]['type'], 'TYPOSQUATTING')
        self.assertIn(matching[0]['technique'], ('levenshtein_distance_1', 'levenshtein_distance_2'))

    def test_levenshtein_distance_2(self):
        """Edit distance 2: 'numpyy' → 'numpy' (extra char + change)."""
        deps = [{"name": "numpyy", "version": "1.0.0"}]
        alerts = self.scanner.scan(deps)
        matching = [a for a in alerts if a.get('similar_to') == 'numpy']
        self.assertTrue(len(matching) > 0)

    # --- Separator confusion ------------------------------------------------
    def test_separator_confusion_dash_vs_underscore(self):
        """python_dateutil vs python-dateutil."""
        deps = [{"name": "python_dateutil", "version": "2.8.0"}]
        alerts = self.scanner.scan(deps, ecosystem='python')
        matching = [a for a in alerts if a.get('technique') == 'separator_confusion']
        self.assertTrue(len(matching) > 0, "Should detect separator confusion for python_dateutil vs python-dateutil")

    # --- Character swap (adjacent transposition) ----------------------------
    def test_character_swap(self):
        """reqeusts → requests (swapped 'u' and 'e')."""
        deps = [{"name": "reqeusts", "version": "1.0.0"}]
        alerts = self.scanner.scan(deps)
        matching = [a for a in alerts if a.get('technique') == 'character_swap']
        self.assertTrue(len(matching) > 0, "Should detect adjacent character swap in 'reqeusts'")

    # --- Repeated characters ------------------------------------------------
    def test_repeated_character(self):
        """flaask → flask (repeated 'a')."""
        deps = [{"name": "flaask", "version": "1.0.0"}]
        alerts = self.scanner.scan(deps)
        matching = [a for a in alerts if a.get('technique') == 'repeated_character']
        self.assertTrue(len(matching) > 0, "Should detect repeated character in 'flaask'")

    # --- Homoglyph substitution ---------------------------------------------
    def test_homoglyph(self):
        """nump1e → uses '1' in place of 'l' which maps to 'numpy' after normalization? 
        Actually let's use 'f1ask' → 'flask' (1 → l)."""
        deps = [{"name": "f1ask", "version": "1.0.0"}]
        alerts = self.scanner.scan(deps)
        matching = [a for a in alerts if a.get('technique') == 'homoglyph']
        self.assertTrue(len(matching) > 0, "Should detect homoglyph substitution in 'f1ask' → 'flask'")

    # --- Version suffix squatting -------------------------------------------
    def test_version_suffix(self):
        """requests2 → requests + '2'."""
        deps = [{"name": "requests2", "version": "1.0.0"}]
        alerts = self.scanner.scan(deps)
        matching = [a for a in alerts if a.get('technique') == 'version_suffix']
        self.assertTrue(len(matching) > 0, "Should detect version suffix squatting in 'requests2'")

    # --- Combosquatting -----------------------------------------------------
    def test_combosquatting(self):
        """requests-lib → embeds 'requests' with a short suffix."""
        deps = [{"name": "requests-lib", "version": "1.0.0"}]
        alerts = self.scanner.scan(deps)
        matching = [a for a in alerts if a.get('technique') == 'combosquatting']
        self.assertTrue(len(matching) > 0, "Should detect combosquatting in 'requests-lib'")

    # --- No false positives for legitimate packages -------------------------
    def test_no_alert_for_exact_match(self):
        """A package that is itself in the popular list should NOT be flagged."""
        deps = [{"name": "requests", "version": "2.31.0"}]
        alerts = self.scanner.scan(deps)
        self.assertEqual(len(alerts), 0, "Should not flag a legitimate popular package")

class TestDependencyGraph(unittest.TestCase):
    """Tests for the DependencyGraph module."""

    def _make_deps(self, names):
        """Helper: create a dependency list from package names."""
        return [{"name": n, "version": "1.0.0"} for n in names]

    # --- Building from Python deps ------------------------------------------
    def test_build_python_graph(self):
        """Flask should gain transitive deps from known_deps.json."""
        graph = DependencyGraph(project_name="test")
        deps = self._make_deps(["flask"])
        graph.build_from_dependencies(deps, ecosystem="python")

        # flask is direct
        self.assertIn("flask", graph.get_direct_deps())
        # known transitive deps of flask
        for sub in ["werkzeug", "jinja2", "click", "itsdangerous", "markupsafe"]:
            self.assertIn(sub, graph.get_all_packages(),
                          f"{sub} should be a transitive dep of flask")
        # markupsafe is transitive, not direct
        self.assertIn("markupsafe", graph.get_transitive_deps())

    # --- Building from npm deps ---------------------------------------------
    def test_build_npm_graph(self):
        """Express should gain transitive deps from known_deps.json."""
        graph = DependencyGraph(project_name="test")
        deps = self._make_deps(["express"])
        graph.build_from_dependencies(deps, ecosystem="npm")

        self.assertIn("express", graph.get_direct_deps())
        # express has many transitive deps in known_deps.json
        self.assertTrue(len(graph.get_transitive_deps()) > 5,
                        "express should have many transitive deps")

    # --- Unknown package is a leaf ------------------------------------------
    def test_unknown_package_leaf(self):
        """A package not in known_deps.json should appear as a leaf node."""
        graph = DependencyGraph(project_name="test")
        deps = self._make_deps(["some-unknown-pkg-xyz"])
        graph.build_from_dependencies(deps, ecosystem="python")

        self.assertIn("some-unknown-pkg-xyz", graph.get_direct_deps())
        self.assertEqual(len(graph.get_dependencies_of("some-unknown-pkg-xyz")), 0)
        self.assertEqual(len(graph.get_transitive_deps()), 0)

    # --- Statistics correctness ---------------------------------------------
    def test_statistics(self):
        """Statistics should report correct direct/transitive counts."""
        graph = DependencyGraph(project_name="test")
        deps = self._make_deps(["requests", "flask"])
        graph.build_from_dependencies(deps, ecosystem="python")

        stats = graph.get_statistics()
        self.assertEqual(stats["direct_dependencies"], 2)
        self.assertTrue(stats["transitive_dependencies"] > 0)
        self.assertEqual(stats["total_packages"],
                         stats["direct_dependencies"] + stats["transitive_dependencies"])
        self.assertTrue(stats["max_depth"] >= 1)

    # --- Cycle detection (no cycles in normal graph) ------------------------
    def test_no_cycles(self):
        """Normal dependency graph should have no cycles."""
        graph = DependencyGraph(project_name="test")
        deps = self._make_deps(["flask"])
        graph.build_from_dependencies(deps, ecosystem="python")

        cycles = graph.detect_cycles()
        self.assertEqual(len(cycles), 0, "Flask graph should have no cycles")

    # --- Cycle detection (injected cycle) -----------------------------------
    def test_detect_injected_cycle(self):
        """A manually injected cycle should be detected."""
        graph = DependencyGraph(project_name="test")
        deps = self._make_deps(["a"])
        graph.build_from_dependencies(deps, ecosystem="python")
        # Manually inject a cycle: a → b → c → a
        graph._add_node("b", is_direct=False)
        graph._add_node("c", is_direct=False)
        graph.add_edge("a", "b")
        graph.add_edge("b", "c")
        graph.add_edge("c", "a")

        cycles = graph.detect_cycles()
        self.assertTrue(len(cycles) > 0, "Should detect the injected cycle")

    # --- Tree rendering contains expected names -----------------------------
    def test_render_tree(self):
        """Rendered tree should contain direct dep names."""
        graph = DependencyGraph(project_name="my-project")
        deps = self._make_deps(["flask", "requests"])
        graph.build_from_dependencies(deps, ecosystem="python")

        tree = graph.render_tree()
        self.assertIn("my-project", tree)
        self.assertIn("flask", tree)
        self.assertIn("requests", tree)
        # transitive deps should appear
        self.assertIn("werkzeug", tree)
        self.assertIn("urllib3", tree)

    # --- Depth calculation --------------------------------------------------
    def test_depth(self):
        """Depth should be >= 1 when transitive deps exist."""
        graph = DependencyGraph(project_name="test")
        deps = self._make_deps(["flask"])
        graph.build_from_dependencies(deps, ecosystem="python")

        # flask → jinja2/werkzeug → markupsafe gives depth ≥ 1
        # (markupsafe is also a direct dep of flask, so BFS depth = 1)
        self.assertTrue(graph.get_depth() >= 1,
                        "Flask's graph should have depth >= 1")

    # --- Stats box formatting -----------------------------------------------
    def test_stats_box_format(self):
        """Stats box should contain border chars and key labels."""
        graph = DependencyGraph(project_name="test")
        deps = self._make_deps(["flask"])
        graph.build_from_dependencies(deps, ecosystem="python")

        box = graph.render_stats_box()
        self.assertIn("┌", box)
        self.assertIn("┘", box)
        self.assertIn("DEPENDENCY GRAPH ANALYSIS", box)
        self.assertIn("Direct dependencies", box)
        self.assertIn("Transitive dependencies", box)
        self.assertIn("Max dependency depth", box)


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
