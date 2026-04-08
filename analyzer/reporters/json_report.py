import json
import os
from datetime import datetime

class JsonReporter:
    def __init__(self, output_path=None):
        self.output_path = output_path or "supply_chain_report.json"
        self.report_data = {
            "metadata": {
                "generated_at": datetime.now().isoformat(),
                "version": "1.0.0"
            },
            "summary": {
                "total_dependencies": 0,
                "vulnerabilities_found": 0,
                "typosquatting_alerts": 0,
                "secrets_found": 0,
                "total_issues": 0,
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
            "recommendations": []
        }

    def add_dependencies(self, dependencies):
        """Add parsed dependencies to report"""
        self.report_data["dependencies"] = dependencies
        self.report_data["summary"]["total_dependencies"] = len(dependencies)

    def add_vulnerability_alerts(self, alerts):
        """Add vulnerability scanning results"""
        for alert in alerts:
            self.report_data["vulnerabilities"].append(alert)
            self.report_data["summary"]["vulnerabilities_found"] += 1
            
            # Track severity
            severity = alert.get("severity", "MEDIUM")
            if severity in self.report_data["summary"]["severity_breakdown"]:
                self.report_data["summary"]["severity_breakdown"][severity] += 1

    def add_typosquatting_alerts(self, alerts):
        """Add typosquatting detection results"""
        for alert in alerts:
            self.report_data["typosquatting"].append(alert)
            self.report_data["summary"]["typosquatting_alerts"] += 1
            # Typosquatting is typically HIGH severity
            self.report_data["summary"]["severity_breakdown"]["HIGH"] += 1

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
            
            # Track severity
            severity = alert.get("severity", "MEDIUM")
            if severity in self.report_data["summary"]["severity_breakdown"]:
                self.report_data["summary"]["severity_breakdown"][severity] += 1

    def add_recommendation(self, recommendation):
        """Add remediation recommendation"""
        self.report_data["recommendations"].append({
            "timestamp": datetime.now().isoformat(),
            "text": recommendation
        })

    def calculate_total_issues(self):
        """Calculate total issues found"""
        self.report_data["summary"]["total_issues"] = (
            self.report_data["summary"]["vulnerabilities_found"] +
            self.report_data["summary"]["typosquatting_alerts"] +
            self.report_data["summary"]["secrets_found"]
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
        report_text = f"""
SUPPLY CHAIN SECURITY ANALYSIS REPORT
Generated: {self.report_data['metadata']['generated_at']}

SUMMARY
-------
Total Dependencies: {self.report_data['summary']['total_dependencies']}
Total Issues Found: {self.report_data['summary']['total_issues']}
Security Score: {self.generate_security_score()}/100

Severity Breakdown:
  - CRITICAL: {self.report_data['summary']['severity_breakdown']['CRITICAL']}
  - HIGH: {self.report_data['summary']['severity_breakdown']['HIGH']}
  - MEDIUM: {self.report_data['summary']['severity_breakdown']['MEDIUM']}
  - LOW: {self.report_data['summary']['severity_breakdown']['LOW']}

Vulnerabilities: {self.report_data['summary']['vulnerabilities_found']}
Typosquatting Alerts: {self.report_data['summary']['typosquatting_alerts']}
Secrets Found: {self.report_data['summary']['secrets_found']}

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
            for s in self.report_data['secrets']:
                report_text += f"  - {s['type']} in {s['file']} (Line: {s.get('line', 'unknown')}): {s['description']}\n"
        
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
            with open(self.output_path, 'w') as f:
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
