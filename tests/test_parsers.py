import unittest
import os
import json
import tempfile
from analyzer.parsers.python_parser import PythonParser
from analyzer.parsers.npm_parser import NpmParser
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
