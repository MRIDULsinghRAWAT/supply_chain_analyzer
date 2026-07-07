import unittest
import os
import json
import tempfile
from unittest.mock import patch, MagicMock

from analyzer.scanners.typosquatting import TyposquattingScanner
from analyzer.scanners.secrets import SecretsScanner
from analyzer.scanners.vulnerability import VulnerabilityScanner

class TestTyposquattingScanner(unittest.TestCase):
    def setUp(self):
        self.scanner = TyposquattingScanner()

    def test_levenshtein_distance_1(self):
        """Edit distance 1: 'requess' -> 'requests' (missing a 't')."""
        deps = [{"name": "requess", "version": "1.0.0"}]
        alerts = self.scanner.scan(deps)
        self.assertTrue(len(alerts) > 0)
        matching = [a for a in alerts if a['similar_to'] == 'requests']
        self.assertTrue(len(matching) > 0)
        self.assertEqual(matching[0]['type'], 'TYPOSQUATTING')
        self.assertIn(matching[0]['technique'], ('levenshtein_distance_1', 'levenshtein_distance_2'))

    def test_levenshtein_distance_2(self):
        """Edit distance 2: 'numpyy' -> 'numpy' (extra char + change)."""
        deps = [{"name": "numpyy", "version": "1.0.0"}]
        alerts = self.scanner.scan(deps)
        matching = [a for a in alerts if a.get('similar_to') == 'numpy']
        self.assertTrue(len(matching) > 0)

    def test_separator_confusion_dash_vs_underscore(self):
        """python_dateutil vs python-dateutil."""
        deps = [{"name": "python_dateutil", "version": "2.8.0"}]
        alerts = self.scanner.scan(deps, ecosystem='python')
        matching = [a for a in alerts if a.get('technique') == 'separator_confusion']
        self.assertTrue(len(matching) > 0, "Should detect separator confusion for python_dateutil vs python-dateutil")

    def test_character_swap(self):
        """reqeusts -> requests (swapped 'u' and 'e')."""
        deps = [{"name": "reqeusts", "version": "1.0.0"}]
        alerts = self.scanner.scan(deps)
        matching = [a for a in alerts if a.get('technique') == 'character_swap']
        self.assertTrue(len(matching) > 0, "Should detect adjacent character swap in 'reqeusts'")

    def test_repeated_character(self):
        """flaask -> flask (repeated 'a')."""
        deps = [{"name": "flaask", "version": "1.0.0"}]
        alerts = self.scanner.scan(deps)
        matching = [a for a in alerts if a.get('technique') == 'repeated_character']
        self.assertTrue(len(matching) > 0, "Should detect repeated character in 'flaask'")

    def test_homoglyph(self):
        """f1ask -> flask (1 -> l)."""
        deps = [{"name": "f1ask", "version": "1.0.0"}]
        alerts = self.scanner.scan(deps)
        matching = [a for a in alerts if a.get('technique') == 'homoglyph']
        self.assertTrue(len(matching) > 0, "Should detect homoglyph substitution in 'f1ask' -> 'flask'")

    def test_version_suffix(self):
        """requests2 -> requests + '2'."""
        deps = [{"name": "requests2", "version": "1.0.0"}]
        alerts = self.scanner.scan(deps)
        matching = [a for a in alerts if a.get('technique') == 'version_suffix']
        self.assertTrue(len(matching) > 0, "Should detect version suffix squatting in 'requests2'")

    def test_combosquatting(self):
        """requests-lib -> embeds 'requests' with a short suffix."""
        deps = [{"name": "requests-lib", "version": "1.0.0"}]
        alerts = self.scanner.scan(deps)
        matching = [a for a in alerts if a.get('technique') == 'combosquatting']
        self.assertTrue(len(matching) > 0, "Should detect combosquatting in 'requests-lib'")

    def test_no_alert_for_exact_match(self):
        """A package that is itself in the popular list should NOT be flagged."""
        deps = [{"name": "requests", "version": "2.31.0"}]
        alerts = self.scanner.scan(deps)
        self.assertEqual(len(alerts), 0, "Should not flag a legitimate popular package")


class TestSecretsScanner(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
    
    def tearDown(self):
        import shutil
        shutil.rmtree(self.temp_dir)

    def test_scan_for_secrets(self):
        scanner = SecretsScanner()
        test_file = os.path.join(self.temp_dir, "config.py")
        with open(test_file, 'w', encoding='utf-8') as f:
            f.write("""
PASSWORD = "supersecret123"
api_key = "sk_test_4eC39HqLyjWDarht1234567890"
""")
        
        secrets = scanner.scan_file(test_file)
        self.assertTrue(len(secrets) > 0)


class TestVulnerabilityScanner(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.old_cwd = os.getcwd()
        os.chdir(self.temp_dir)

    def tearDown(self):
        os.chdir(self.old_cwd)
        import shutil
        shutil.rmtree(self.temp_dir)

    def test_check_version_vulnerable(self):
        scanner = VulnerabilityScanner(use_cache=False)
        # Check standard operators
        self.assertTrue(scanner.check_version_vulnerable("3.2.0", "<3.2.13,>=3.2"))
        self.assertFalse(scanner.check_version_vulnerable("3.2.14", "<3.2.13,>=3.2"))
        self.assertFalse(scanner.check_version_vulnerable("3.1.0", "<3.2.13,>=3.2"))
        self.assertTrue(scanner.check_version_vulnerable("1.0.0", "*"))
        self.assertTrue(scanner.check_version_vulnerable("1.0.0", None))

    def test_scan_with_fallback_mock_db(self):
        scanner = VulnerabilityScanner(use_cache=False)
        
        # requests <2.20.0 is vulnerable to CVE-2018-18074 according to mock_db
        deps = [
            {"name": "requests", "version": "2.19.0"},
            {"name": "requests", "version": "2.21.0"}
        ]
        
        alerts = scanner.scan(deps)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["package"], "requests")
        self.assertEqual(alerts[0]["version"], "2.19.0")
        self.assertEqual(alerts[0]["cve"], "CVE-2018-18074")

    def test_caching_behavior(self):
        # Instantiate with cache file in temp_dir
        scanner = VulnerabilityScanner(use_cache=True)
        scanner.cache_file = "temp_vuln_cache.json"
        
        # Populate cache
        scanner.vuln_cache["some-pkg"] = [
            {"cve": "CVE-9999-9999", "severity": "HIGH", "affected_versions": ">=1.0.0", "summary": "Bad vuln"}
        ]
        scanner.save_cache()
        
        # Instantiate new scanner to load cache
        scanner2 = VulnerabilityScanner(use_cache=True)
        scanner2.cache_file = "temp_vuln_cache.json"
        scanner2.load_cache()
        
        self.assertIn("some-pkg", scanner2.vuln_cache)
        self.assertEqual(scanner2.vuln_cache["some-pkg"][0]["cve"], "CVE-9999-9999")

    @patch('requests.post')
    def test_query_github_advisory_success(self, mock_post):
        # Mock successful GraphQL response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": {
                "securityVulnerabilities": {
                    "nodes": [
                        {
                            "advisory": {
                                "cveId": "CVE-2023-1111",
                                "severity": "CRITICAL",
                                "summary": "GraphQL Mocked Advisory Summary",
                                "description": "GraphQL Mocked Advisory Description"
                            },
                            "vulnerableVersionRange": "<2.0.0"
                        }
                    ]
                }
            }
        }
        mock_post.return_value = mock_response

        scanner = VulnerabilityScanner(use_cache=False)
        vulns = scanner.query_github_advisory("test-package")
        
        self.assertEqual(len(vulns), 1)
        self.assertEqual(vulns[0]["cve"], "CVE-2023-1111")
        self.assertEqual(vulns[0]["severity"], "CRITICAL")
        self.assertEqual(vulns[0]["affected_versions"], "<2.0.0")

if __name__ == '__main__':
    unittest.main()
