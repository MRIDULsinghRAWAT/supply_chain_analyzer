import argparse
import os
from analyzer.parsers.python_parser import PythonParser
from analyzer.parsers.npm_parser import NpmParser
from analyzer.scanners.typosquatting import TyposquattingScanner
from analyzer.scanners.vulnerability import VulnerabilityScanner
from analyzer.scanners.secrets import SecretsScanner
from analyzer.reporters.console import ConsoleReporter
from analyzer.reporters.json_report import JsonReporter

def main():
    # Setup Argument Parser for CLI
    parser = argparse.ArgumentParser(description="Supply Chain Security Analyzer")
    parser.add_argument('-f', '--file', help="Path to requirements.txt or package.json")
    parser.add_argument('-d', '--directory', help="Scan entire directory for secrets")
    parser.add_argument('-o', '--output', help="Output JSON report file path (default: supply_chain_report.json)")
    parser.add_argument('--scan-secrets', action='store_true', help="Enable secret scanning")
    parser.add_argument('--scan-git', action='store_true', help="Scan git history for secrets")
    parser.add_argument('--no-vuln', action='store_true', help="Skip vulnerability scanning")
    parser.add_argument('--no-typo', action='store_true', help="Skip typosquatting scanning")
    
    args = parser.parse_args()

    # Validate arguments
    if not args.file and not args.directory:
        parser.print_help()
        return

    reporter = ConsoleReporter()
    json_reporter = JsonReporter(args.output or "supply_chain_report.json")

    dependencies = []

    # ===== PHASE 1: PARSING =====
    if args.file:
        file_ext = os.path.splitext(args.file)[1].lower()
        
        if file_ext == '.txt':
            # Parse Python requirements.txt
            reporter.print_header(f"Starting Analysis on {args.file}")
            try:
                python_parser = PythonParser(args.file)
                dependencies = python_parser.parse()
                reporter.print_success(f"Successfully parsed {len(dependencies)} Python dependencies.")
            except Exception as e:
                reporter.print_danger(f"Error parsing: {str(e)}")
                return
        
        elif file_ext == '.json':
            # Parse npm package.json
            reporter.print_header(f"Starting Analysis on {args.file}")
            try:
                npm_parser = NpmParser(args.file)
                dependencies = npm_parser.parse()
                reporter.print_success(f"Successfully parsed {len(dependencies)} npm dependencies.")
                
                # Also try to scan transitive dependencies
                node_modules_path = os.path.join(os.path.dirname(args.file), 'node_modules')
                if os.path.exists(node_modules_path):
                    transitive = npm_parser.get_transitive_dependencies(node_modules_path)
                    dependencies.extend(transitive)
                    reporter.print_success(f"Found {len(transitive)} transitive dependencies.")
            except Exception as e:
                reporter.print_danger(f"Error parsing: {str(e)}")
                return
        else:
            reporter.print_danger(f"Unsupported file type: {file_ext}")
            return

        json_reporter.add_dependencies(dependencies)

    # ===== PHASE 2: SCANNING =====
    
    # Typosquatting Scanner
    if not args.no_typo and dependencies:
        typo_scanner = TyposquattingScanner()
        reporter.print_header("Scanning for Typosquatting")
        typo_alerts = typo_scanner.scan(dependencies)
        if not typo_alerts:
            reporter.print_success("No typosquatting detected.")
        else:
            for alert in typo_alerts:
                reporter.print_warning(f"{alert['package']} - {alert['message']}")
        json_reporter.add_typosquatting_alerts(typo_alerts)

    # Vulnerability Scanner
    if not args.no_vuln and dependencies:
        vuln_scanner = VulnerabilityScanner()
        reporter.print_header("Scanning for Vulnerabilities (SCA)")
        vuln_alerts = vuln_scanner.scan(dependencies)
        if not vuln_alerts:
            reporter.print_success("No known vulnerabilities found.")
        else:
            for alert in vuln_alerts:
                severity_str = f"[{alert['severity']}]" if 'severity' in alert else ""
                reporter.print_danger(f"{alert['package']} (v{alert['version']}) - {severity_str} {alert['message']}")
        json_reporter.add_vulnerability_alerts(vuln_alerts)

    # Secrets Scanner
    if args.scan_secrets:
        secrets_scanner = SecretsScanner()
        
        if args.directory:
            reporter.print_header("Scanning Directory for Secrets")
            secrets = secrets_scanner.scan_directory(args.directory)
        elif args.file:
            reporter.print_header("Scanning File for Secrets")
            secrets = secrets_scanner.scan_file(args.file)
        else:
            secrets = []
        
        if not secrets:
            reporter.print_success("No secrets detected.")
        else:
            for alert in secrets:
                reporter.print_danger(f"{alert['type']} in {alert['file']} (Line {alert.get('line', '?')}): {alert['description']}")
        json_reporter.add_secrets_alerts(secrets)

    # Git History Secret Scanning
    if args.scan_git:
        secrets_scanner = SecretsScanner()
        reporter.print_header("Scanning Git History for Secrets")
        
        repo_path = args.directory or os.path.dirname(args.file) if args.file else '.'
        
        git_secrets = secrets_scanner.scan_git_history(repo_path)
        if not git_secrets:
            reporter.print_success("No secrets in git history.")
        else:
            for alert in git_secrets:
                reporter.print_danger(f"{alert['type']} in commit {alert.get('commit', '?')}: {alert['description']}")
        json_reporter.add_secrets_alerts(git_secrets)

    # ===== PHASE 3: REPORTING =====
    reporter.print_header("Generating Report")
    
    # Add remediation recommendations
    summary = json_reporter.report_data["summary"]
    if summary["vulnerabilities_found"] > 0:
        json_reporter.add_recommendation(f"Update {summary['vulnerabilities_found']} vulnerable packages to latest patched versions")
    if summary["typosquatting_alerts"] > 0:
        json_reporter.add_recommendation("Review and remove potentially malicious packages flagged for typosquatting")
    if summary["secrets_found"] > 0:
        json_reporter.add_recommendation("Rotate exposed credentials and implement secret scanning in CI/CD")
    
    # Save JSON report
    report_path = json_reporter.save_json()
    reporter.print_success(f"JSON report saved to {report_path}")
    
    # Print summary
    json_reporter.print_summary()

if __name__ == "__main__":
    main()