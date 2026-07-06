import argparse
import os
import sys

# Ensure stdout supports Unicode (box-drawing chars, etc.) on Windows
if sys.stdout.encoding and sys.stdout.encoding.lower() != 'utf-8':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except AttributeError:
        pass  # Python < 3.7

from analyzer.parsers.python_parser import PythonParser
from analyzer.parsers.npm_parser import NpmParser
from analyzer.parsers.ruby_parser import RubyParser
from analyzer.parsers.maven_parser import MavenParser
from analyzer.scanners.typosquatting import TyposquattingScanner
from analyzer.scanners.vulnerability import VulnerabilityScanner
from analyzer.scanners.secrets import SecretsScanner
from analyzer.scanners.license import LicenseScanner
from analyzer.scanners.dep_confusion import DependencyConfusionScanner
from analyzer.scanners.pipeline import PipelineScanner
from analyzer.scanners.version_analyzer import VersionAnalyzer
from analyzer.graph.dependency_graph import DependencyGraph
from analyzer.reporters.console import ConsoleReporter
from analyzer.reporters.json_report import JsonReporter
from analyzer.reporters.dashboard import DashboardReporter

def main():
    # Setup Argument Parser for CLI
    parser = argparse.ArgumentParser(description="Supply Chain Security Analyzer")
    parser.add_argument('-f', '--file', help="Path to requirements.txt, package.json, Gemfile, or pom.xml")
    parser.add_argument('-d', '--directory', help="Scan entire directory for secrets, pipelines, and artifacts")
    parser.add_argument('-o', '--output', help="Output JSON report file path (default: supply_chain_report.json)")
    parser.add_argument('--scan-secrets', action='store_true', help="Enable secret scanning")
    parser.add_argument('--scan-git', action='store_true', help="Scan git history for secrets")
    parser.add_argument('--no-vuln', action='store_true', help="Skip vulnerability scanning")
    parser.add_argument('--no-typo', action='store_true', help="Skip typosquatting scanning")
    parser.add_argument('--graph', action='store_true', help="Show dependency graph visualization")
    parser.add_argument('--graph-depth', type=int, default=None, help="Max depth for graph tree (default: unlimited)")
    parser.add_argument('--dashboard', action='store_true', help="Show terminal security dashboard")
    
    args = parser.parse_args()

    # Validate arguments
    if not args.file and not args.directory:
        parser.print_help()
        return

    reporter = ConsoleReporter()
    json_reporter = JsonReporter(args.output or "supply_chain_report.json")

    dependencies = []
    ecosystem = None  # Will be set based on file type

    # ===== PHASE 1: PARSING =====
    if args.file:
        file_ext = os.path.splitext(args.file)[1].lower()
        file_name = os.path.basename(args.file).lower()
        
        if file_ext == '.txt':
            # Parse Python requirements.txt
            ecosystem = 'python'
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
            ecosystem = 'npm'
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
        
        elif file_name == 'gemfile' or file_ext in ('.gemfile', '.rb'):
            # Parse Ruby Gemfile
            ecosystem = 'ruby'
            reporter.print_header(f"Starting Analysis on {args.file}")
            try:
                ruby_parser = RubyParser(args.file)
                dependencies = ruby_parser.parse()
                reporter.print_success(f"Successfully parsed {len(dependencies)} Ruby dependencies.")
            except Exception as e:
                reporter.print_danger(f"Error parsing: {str(e)}")
                return

        elif file_name == 'pom.xml' or file_ext in ('.xml', '.pom'):
            # Parse Maven pom.xml
            ecosystem = 'maven'
            reporter.print_header(f"Starting Analysis on {args.file}")
            try:
                maven_parser = MavenParser(args.file)
                dependencies = maven_parser.parse()
                reporter.print_success(f"Successfully parsed {len(dependencies)} Maven dependencies.")
            except Exception as e:
                reporter.print_danger(f"Error parsing: {str(e)}")
                return
        else:
            reporter.print_danger(f"Unsupported file type: {file_ext}")
            return

        json_reporter.add_dependencies(dependencies)

    # ===== PHASE 1.5: DEPENDENCY GRAPH =====
    graph = None
    all_resolved_deps = []
    
    # If we parsed direct dependencies, construct graph to resolve transitives
    if dependencies:
        project_name = os.path.basename(args.file) if args.file else "project"
        graph = DependencyGraph(project_name=project_name)
        graph.build_from_dependencies(dependencies, ecosystem=ecosystem)
        
        # Build all_resolved_deps including both direct and transitive
        for name, meta in graph.metadata.items():
            all_resolved_deps.append({
                "name": name,
                "version": meta.get("version", "latest"),
                "is_direct": meta.get("is_direct", False),
                "ecosystem": ecosystem
            })
            
        if args.graph:
            reporter.print_header("Building Dependency Graph")
            # Print ASCII tree
            reporter.print_info("Dependency Tree:")
            print()
            print(graph.render_tree(max_depth=args.graph_depth))
            print()

            # Print stats box
            print(graph.render_stats_box())
            print()

            # Add to JSON report
            json_reporter.add_dependency_graph(graph.to_dict())
    else:
        # No dependency file provided, scan directory directly for secrets/pipelines/artifacts
        pass

    # If no graph was built (no deps), fall back to direct deps list (empty)
    scan_deps_list = all_resolved_deps if all_resolved_deps else dependencies

    # Helper to calculate blast radius path
    def enrich_transitive_alerts(alerts):
        if not graph:
            return
        for alert in alerts:
            pkg_name = alert.get("package")
            if pkg_name:
                path = graph.find_path_to(pkg_name)
                if len(path) > 1:
                    alert["dependency_path"] = " -> ".join(path)
                    alert["message"] += f" (Transitive dependency path: {alert['dependency_path']})"
                    # Mark severity as slightly lower for transitive if needed, or keep standard
                    alert["is_transitive"] = True

    # ===== PHASE 2: SCANNING =====
    
    # Typosquatting Scanner
    if not args.no_typo and scan_deps_list:
        typo_scanner = TyposquattingScanner()
        reporter.print_header("Scanning for Typosquatting")
        typo_alerts = typo_scanner.scan(scan_deps_list, reporter=reporter, ecosystem=ecosystem)
        enrich_transitive_alerts(typo_alerts)
        
        if not typo_alerts:
            reporter.print_success("No typosquatting detected.")
        else:
            for alert in typo_alerts:
                severity = alert.get('severity', 'HIGH')
                technique = alert.get('technique', 'unknown')
                confidence = alert.get('confidence', 'MEDIUM')
                path_suffix = f" [Transitive: {alert['dependency_path']}]" if 'dependency_path' in alert else ""
                
                if severity == 'CRITICAL':
                    reporter.print_danger(
                        f"[{severity}] {alert['package']} - {alert['message']}{path_suffix} "
                        f"(technique: {technique}, confidence: {confidence})")
                else:
                    reporter.print_warning(
                        f"[{severity}] {alert['package']} - {alert['message']}{path_suffix} "
                        f"(technique: {technique}, confidence: {confidence})")
        json_reporter.add_typosquatting_alerts(typo_alerts)

    # Vulnerability Scanner (SCA)
    if not args.no_vuln and scan_deps_list:
        vuln_scanner = VulnerabilityScanner()
        reporter.print_header("Scanning for Vulnerabilities (SCA)")
        vuln_alerts = vuln_scanner.scan(scan_deps_list, reporter=reporter)
        enrich_transitive_alerts(vuln_alerts)
        
        if not vuln_alerts:
            reporter.print_success("No known vulnerabilities found.")
        else:
            for alert in vuln_alerts:
                severity_str = f"[{alert['severity']}]" if 'severity' in alert else ""
                path_suffix = f" [Transitive: {alert['dependency_path']}]" if 'dependency_path' in alert else ""
                reporter.print_danger(f"{alert['package']} (v{alert['version']}) - {severity_str} {alert['message']}{path_suffix}")
        json_reporter.add_vulnerability_alerts(vuln_alerts)

    # Secrets Scanner
    if args.scan_secrets:
        secrets_scanner = SecretsScanner()
        
        if args.directory:
            reporter.print_header("Scanning Directory for Secrets")
            secrets = secrets_scanner.scan_directory(args.directory, reporter=reporter)
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
        
        git_secrets = secrets_scanner.scan_git_history(repo_path, reporter=reporter)
        if not git_secrets:
            reporter.print_success("No secrets in git history.")
        else:
            for alert in git_secrets:
                reporter.print_danger(f"{alert['type']} in commit {alert.get('commit', '?')}: {alert['description']}")
        json_reporter.add_secrets_alerts(git_secrets)

    # License Compliance Scanner
    if scan_deps_list:
        license_scanner = LicenseScanner()
        reporter.print_header("Scanning License Compliance")
        lic_alerts, lic_info = license_scanner.scan(scan_deps_list, ecosystem=ecosystem, reporter=reporter)
        enrich_transitive_alerts(lic_alerts)
        
        if not lic_alerts:
            reporter.print_success("No license compliance issues or conflicts found.")
        else:
            for alert in lic_alerts:
                path_suffix = f" [Transitive: {alert['dependency_path']}]" if 'dependency_path' in alert else ""
                reporter.print_warning(f"[{alert['severity']}] {alert.get('package', 'project')}: {alert['message']}{path_suffix}")
        json_reporter.add_license_alerts(lic_alerts)

    # Dependency Confusion Scanner
    if scan_deps_list or args.directory:
        dep_confusion_scanner = DependencyConfusionScanner()
        reporter.print_header("Scanning for Dependency Confusion")
        scan_dir = args.directory or (os.path.dirname(args.file) if args.file else '.')
        
        dc_config_alerts = dep_confusion_scanner.scan_configs(scan_dir)
        dc_dep_alerts = dep_confusion_scanner.scan_dependencies(dependencies, ecosystem)
        dc_alerts = dc_config_alerts + dc_dep_alerts
        enrich_transitive_alerts(dc_alerts)
        
        if not dc_alerts:
            reporter.print_success("No dependency confusion risks detected.")
        else:
            for alert in dc_alerts:
                target_label = alert.get('package', alert.get('file', 'project'))
                reporter.print_danger(f"[{alert['severity']}] {target_label}: {alert['message']}")
        json_reporter.add_dep_confusion_alerts(dc_alerts)

    # CI/CD Pipeline Security Scanner
    if args.directory or args.file:
        pipeline_scanner = PipelineScanner()
        reporter.print_header("Scanning CI/CD Pipelines")
        scan_dir = args.directory or (os.path.dirname(args.file) if args.file else '.')
        
        pipeline_alerts = pipeline_scanner.scan_directory(scan_dir)
        if not pipeline_alerts:
            reporter.print_success("No CI/CD pipeline risks detected.")
        else:
            for alert in pipeline_alerts:
                reporter.print_danger(f"[{alert['severity']}] {alert['file']} (Line {alert['line']}): {alert['message']}")
        json_reporter.add_pipeline_alerts(pipeline_alerts)

    # Version Constraint & Outdated Package Analysis
    if dependencies:
        version_analyzer = VersionAnalyzer()
        reporter.print_header("Analyzing Dependency Version Constraints")
        
        version_alerts = version_analyzer.scan(dependencies, ecosystem=ecosystem, reporter=reporter)
        if not version_alerts:
            reporter.print_success("All direct dependencies are up to date.")
        else:
            for alert in version_alerts:
                reporter.print_warning(f"[{alert['severity']}] {alert['package']} (installed: {alert['installed_version']}, latest: {alert['latest_version']}): {alert['message']}")
        json_reporter.add_version_alerts(version_alerts)



    # ===== PHASE 3: REPORTING =====
    reporter.print_header("Generating Report")
    
    # Add remediation recommendations based on all scanned findings
    summary = json_reporter.report_data["summary"]
    if summary["vulnerabilities_found"] > 0:
        json_reporter.add_recommendation(f"Update {summary['vulnerabilities_found']} vulnerable packages to latest patched versions")
    if summary["typosquatting_alerts"] > 0:
        json_reporter.add_recommendation("Review and remove potentially malicious packages flagged for typosquatting")
    if summary["secrets_found"] > 0:
        json_reporter.add_recommendation("Rotate exposed credentials and implement secret scanning in CI/CD")
    if summary["licenses_found"] > 0:
        json_reporter.add_recommendation("Review and resolve restrictive copyleft license risks and conflicts")
    if summary["dep_confusion_issues"] > 0:
        json_reporter.add_recommendation("Secure private package registers, scope scopes, or register placeholders publicly to prevent dependency confusion")
    if summary["pipeline_issues"] > 0:
        json_reporter.add_recommendation("Pin third-party Actions to full commit SHAs and remove dangerous command lines from CI/CD")
    if summary["versions_outdated"] > 0:
        json_reporter.add_recommendation(f"Upgrade {summary['versions_outdated']} outdated packages to their latest versions")

    
    # Save JSON report
    report_path = json_reporter.save_json()
    reporter.print_success(f"JSON report saved to {report_path}")
    
    # Print either dashboard or standard summary
    if args.dashboard:
        dashboard = DashboardReporter(json_reporter.get_json_dict())
        dashboard.render()
    else:
        json_reporter.print_summary()

if __name__ == "__main__":
    main()