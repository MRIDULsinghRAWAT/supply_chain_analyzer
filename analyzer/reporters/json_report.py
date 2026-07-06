import json
import os
from datetime import datetime

class JsonReporter:
    def __init__(self, output_path=None):
        self.output_path = output_path or "supply_chain_report.json"
        self.report_data = {
            "metadata": {
                "generated_at": datetime.now().isoformat(),
                "version": "1.1.0"
            },
            "summary": {
                "total_dependencies": 0,
                "vulnerabilities_found": 0,
                "typosquatting_alerts": 0,
                "secrets_found": 0,
                "licenses_found": 0,
                "dep_confusion_issues": 0,
                "pipeline_issues": 0,
                "versions_outdated": 0,
                "artifact_issues": 0,
                "total_issues": 0,
                "severity_breakdown": {
                    "CRITICAL": 0,
                    "HIGH": 0,
                    "MEDIUM": 0,
                    "LOW": 0
                }
            },
            "dependencies": [],
            "dependency_graph": None,
            "vulnerabilities": [],
            "typosquatting": [],
            "secrets": [],
            "licenses": [],
            "dep_confusion": [],
            "pipeline": [],
            "versions": [],
            "artifacts": [],
            "recommendations": []
        }

    def add_dependencies(self, dependencies):
        """Add parsed dependencies to report"""
        self.report_data["dependencies"] = dependencies
        self.report_data["summary"]["total_dependencies"] = len(dependencies)

    def add_dependency_graph(self, graph_data):
        """Add dependency graph analysis to report"""
        self.report_data["dependency_graph"] = graph_data

    def _track_severity(self, alert, default_severity="MEDIUM"):
        severity = alert.get("severity", default_severity).upper()
        if severity in self.report_data["summary"]["severity_breakdown"]:
            self.report_data["summary"]["severity_breakdown"][severity] += 1
        else:
            self.report_data["summary"]["severity_breakdown"]["MEDIUM"] += 1

    def add_vulnerability_alerts(self, alerts):
        """Add vulnerability scanning results"""
        for alert in alerts:
            self.report_data["vulnerabilities"].append(alert)
            self.report_data["summary"]["vulnerabilities_found"] += 1
            self._track_severity(alert, "HIGH")

    def add_typosquatting_alerts(self, alerts):
        """Add typosquatting detection results"""
        for alert in alerts:
            self.report_data["typosquatting"].append(alert)
            self.report_data["summary"]["typosquatting_alerts"] += 1
            self._track_severity(alert, "HIGH")

    def add_secrets_alerts(self, alerts):
        """Add secrets scanning results"""
        for alert in alerts:
            self.report_data["secrets"].append({
                "type": alert.get("type"),
                "file": alert.get("file"),
                "severity": alert.get("severity"),
                "description": alert.get("description"),
                "line": alert.get("line"),
                "commit": alert.get("commit")
            })
            self.report_data["summary"]["secrets_found"] += 1
            self._track_severity(alert, "HIGH")

    def add_license_alerts(self, alerts):
        """Add license scanning results"""
        for alert in alerts:
            self.report_data["licenses"].append(alert)
            self.report_data["summary"]["licenses_found"] += 1
            self._track_severity(alert, "MEDIUM")

    def add_dep_confusion_alerts(self, alerts):
        """Add dependency confusion scanning results"""
        for alert in alerts:
            self.report_data["dep_confusion"].append(alert)
            self.report_data["summary"]["dep_confusion_issues"] += 1
            self._track_severity(alert, "HIGH")

    def add_pipeline_alerts(self, alerts):
        """Add CI/CD pipeline scanning results"""
        for alert in alerts:
            self.report_data["pipeline"].append(alert)
            self.report_data["summary"]["pipeline_issues"] += 1
            self._track_severity(alert, "MEDIUM")

    def add_version_alerts(self, alerts):
        """Add version constraint / outdated dependencies results"""
        for alert in alerts:
            self.report_data["versions"].append(alert)
            self.report_data["summary"]["versions_outdated"] += 1
            self._track_severity(alert, "LOW")

    def add_artifact_alerts(self, alerts):
        """Add Dockerfile / build artifact scanning results"""
        for alert in alerts:
            self.report_data["artifacts"].append(alert)
            self.report_data["summary"]["artifact_issues"] += 1
            self._track_severity(alert, "MEDIUM")

    def add_recommendation(self, recommendation):
        """Add remediation recommendation"""
        self.report_data["recommendations"].append({
            "timestamp": datetime.now().isoformat(),
            "text": recommendation
        })

    def calculate_total_issues(self):
        """Calculate total issues found"""
        s = self.report_data["summary"]
        s["total_issues"] = (
            s["vulnerabilities_found"] +
            s["typosquatting_alerts"] +
            s["secrets_found"] +
            s["licenses_found"] +
            s["dep_confusion_issues"] +
            s["pipeline_issues"] +
            s["versions_outdated"] +
            s["artifact_issues"]
        )

    def generate_security_score(self):
        """Generate security score (0-100)"""
        score = 100
        
        # Deduct points based on severity
        critical_count = self.report_data["summary"]["severity_breakdown"]["CRITICAL"]
        high_count = self.report_data["summary"]["severity_breakdown"]["HIGH"]
        medium_count = self.report_data["summary"]["severity_breakdown"]["MEDIUM"]
        low_count = self.report_data["summary"]["severity_breakdown"]["LOW"]
        
        score -= critical_count * 15
        score -= high_count * 8
        score -= medium_count * 3
        score -= low_count * 1
        
        return max(0, score)  # Ensure score doesn't go below 0

    def generate_report_text(self):
        """Generate human-readable report"""
        self.calculate_total_issues()
        s = self.report_data['summary']
        report_text = f"""
SUPPLY CHAIN SECURITY ANALYSIS REPORT
Generated: {self.report_data['metadata']['generated_at']}

SUMMARY
-------
Total Dependencies: {s['total_dependencies']}
Total Issues Found: {s['total_issues']}
Security Score: {self.generate_security_score()}/100

Severity Breakdown:
  - CRITICAL: {s['severity_breakdown']['CRITICAL']}
  - HIGH: {s['severity_breakdown']['HIGH']}
  - MEDIUM: {s['severity_breakdown']['MEDIUM']}
  - LOW: {s['severity_breakdown']['LOW']}

Issues by Category:
  - Vulnerabilities: {s['vulnerabilities_found']}
  - Typosquatting Alerts: {s['typosquatting_alerts']}
  - Secrets Found: {s['secrets_found']}
  - License Risks/Conflicts: {s['licenses_found']}
  - Dependency Confusion Risks: {s['dep_confusion_issues']}
  - CI/CD Pipeline Risks: {s['pipeline_issues']}
  - Outdated Dependencies: {s['versions_outdated']}
  - Container / Artifact Risks: {s['artifact_issues']}

DETAILED FINDINGS
-----------------
"""
        
        if self.report_data['vulnerabilities']:
            report_text += "\nVulnerabilities:\n"
            for v in self.report_data['vulnerabilities']:
                report_text += f"  - {v['package']} (v{v['version']}): {v['message']}\n"
        
        if self.report_data['typosquatting']:
            report_text += "\nTyposquatting Alerts:\n"
            for t in self.report_data['typosquatting']:
                report_text += f"  - {t['package']}: {t['message']}\n"
        
        if self.report_data['secrets']:
            report_text += "\nSecrets Found:\n"
            for sec in self.report_data['secrets']:
                report_text += f"  - {sec['type']} in {sec['file']} (Line: {sec.get('line', 'unknown')}): {sec['description']}\n"
        
        if self.report_data['licenses']:
            report_text += "\nLicense Risks & Conflicts:\n"
            for lic in self.report_data['licenses']:
                report_text += f"  - {lic.get('package', 'project')}: {lic['message']}\n"

        if self.report_data['dep_confusion']:
            report_text += "\nDependency Confusion Risks:\n"
            for dc in self.report_data['dep_confusion']:
                report_text += f"  - {dc['package']}: {dc['message']}\n"

        if self.report_data['pipeline']:
            report_text += "\nCI/CD Pipeline Risks:\n"
            for p in self.report_data['pipeline']:
                report_text += f"  - {p.get('file', 'pipeline')}: {p['message']}\n"

        if self.report_data['versions']:
            report_text += "\nOutdated Dependencies:\n"
            for v in self.report_data['versions']:
                report_text += f"  - {v['package']} (installed: {v['installed_version']}, latest: {v['latest_version']}): {v['message']}\n"

        if self.report_data['artifacts']:
            report_text += "\nContainer & Build Artifact Risks:\n"
            for art in self.report_data['artifacts']:
                report_text += f"  - {art.get('file', 'Dockerfile')}: {art['message']}\n"

        if self.report_data['recommendations']:
            report_text += "\nRECOMMENDATIONS\n"
            for rec in self.report_data['recommendations']:
                report_text += f"  - {rec['text']}\n"
        
        return report_text

    def save_json(self):
        """Save report as JSON file"""
        self.calculate_total_issues()
        self.report_data["metadata"]["security_score"] = self.generate_security_score()
        
        try:
            with open(self.output_path, 'w', encoding='utf-8') as f:
                json.dump(self.report_data, f, indent=2)
            return self.output_path
        except IOError as e:
            raise Exception(f"Failed to save report: {str(e)}")

    def get_json_dict(self):
        """Return report as dictionary"""
        self.calculate_total_issues()
        self.report_data["metadata"]["security_score"] = self.generate_security_score()
        return self.report_data

    def print_summary(self):
        """Print summary to console"""
        print(self.generate_report_text())
