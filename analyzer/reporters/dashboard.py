from colorama import Fore, Style, init
import sys

class DashboardReporter:
    def __init__(self, report_data):
        self.data = report_data
        init(autoreset=True)

    def render(self):
        """Render the beautiful security dashboard to terminal"""
        metadata = self.data.get("metadata", {})
        summary = self.data.get("summary", {})
        score = metadata.get("security_score", 100)
        
        # Determine score colors
        if score >= 80:
            score_color = Fore.GREEN
            status_text = " SECURE "
            status_bg = "\033[42m\033[30m" # Green bg, Black text
        elif score >= 50:
            score_color = Fore.YELLOW
            status_text = " WARNING "
            status_bg = "\033[43m\033[30m" # Yellow bg, Black text
        else:
            score_color = Fore.RED
            status_text = " VULNERABLE "
            status_bg = "\033[41m\033[37m" # Red bg, White text

        print(f"\n{Style.BRIGHT}{Fore.CYAN}┌──────────────────────────────────────────────────────────────────────────────┐")
        print(f"{Style.BRIGHT}{Fore.CYAN}|               SUPPLY CHAIN SECURITY ANALYZER DASHBOARD                      |")
        print(f"{Style.BRIGHT}{Fore.CYAN}└──────────────────────────────────────────────────────────────────────────────┘")
        
        # Meta info
        gen_time = metadata.get("generated_at", "")[:19].replace("T", " ")
        print(f" Generated: {Fore.WHITE}{gen_time}  |  Version: {Fore.WHITE}{metadata.get('version', '1.1.0')}")
        print("-" * 80)
        
        # Score Gauge
        gauge_width = 30
        filled = int((score / 100) * gauge_width)
        empty = gauge_width - filled
        gauge = score_color + "█" * filled + Fore.BLACK + "░" * empty
        
        score_display = f"{score_color}{score}/100"
        print(f" {Style.BRIGHT}Security Health Score: [{gauge}{Style.BRIGHT}] {score_display}   {status_bg}{Style.BRIGHT}{status_text}{Style.RESET_ALL}")
        print("-" * 80)
        
        # Summary Grid
        print(f" {Style.BRIGHT}{Fore.BLUE}SUMMARY OF FINDINGS:")
        print(" ┌──────────────────────────────────────┬──────────────────────────────────────┐")
        
        def print_row(label1, count1, label2, count2, fore1=Fore.WHITE, fore2=Fore.WHITE):
            c1_str = f"{fore1}{count1:<4}"
            c2_str = f"{fore2}{count2:<4}"
            print(f" │ {label1:<28} : {c1_str} │ {label2:<28} : {c2_str} │")

        vuln_color = Fore.RED if summary.get("vulnerabilities_found", 0) > 0 else Fore.GREEN
        typo_color = Fore.YELLOW if summary.get("typosquatting_alerts", 0) > 0 else Fore.GREEN
        sec_color = Fore.RED if summary.get("secrets_found", 0) > 0 else Fore.GREEN
        lic_color = Fore.YELLOW if summary.get("licenses_found", 0) > 0 else Fore.GREEN
        dc_color = Fore.RED if summary.get("dep_confusion_issues", 0) > 0 else Fore.GREEN
        pip_color = Fore.YELLOW if summary.get("pipeline_issues", 0) > 0 else Fore.GREEN
        ver_color = Fore.WHITE if summary.get("versions_outdated", 0) > 0 else Fore.GREEN
        art_color = Fore.YELLOW if summary.get("artifact_issues", 0) > 0 else Fore.GREEN

        print_row("Vulnerabilities (SCA)", summary.get("vulnerabilities_found", 0), "Typosquatting Alerts", summary.get("typosquatting_alerts", 0), vuln_color, typo_color)
        print_row("Exposed Secrets", summary.get("secrets_found", 0), "License Risks & Conflicts", summary.get("licenses_found", 0), sec_color, lic_color)
        print_row("Dependency Confusion", summary.get("dep_confusion_issues", 0), "CI/CD Pipeline Risks", summary.get("pipeline_issues", 0), dc_color, pip_color)
        print_row("Outdated Dependencies", summary.get("versions_outdated", 0), "Container / Artifact Risks", summary.get("artifact_issues", 0), ver_color, art_color)
        
        print(" └──────────────────────────────────────┴──────────────────────────────────────┘")
        
        # Severity Breakdown
        s_break = summary.get("severity_breakdown", {})
        print(f" Severity Breakdown: "
              f"{Fore.RED}{Style.BRIGHT}CRITICAL: {s_break.get('CRITICAL', 0)}  "
              f"{Fore.YELLOW}{Style.BRIGHT}HIGH: {s_break.get('HIGH', 0)}  "
              f"{Fore.CYAN}MEDIUM: {s_break.get('MEDIUM', 0)}  "
              f"{Fore.WHITE}LOW: {s_break.get('LOW', 0)}")
        print("-" * 80)
        
        # Recommendations / Action Items
        recs = self.data.get("recommendations", [])
        if recs:
            print(f" {Style.BRIGHT}{Fore.MAGENTA}RECOMMENDED ACTIONS:")
            for idx, rec in enumerate(recs, 1):
                print(f"  {Fore.MAGENTA}{idx}. {Style.RESET_ALL}{rec.get('text')}")
        else:
            print(f" {Fore.GREEN}[OK] No immediate remediation actions needed. Keep up the good work!")
        print("-" * 80)
        print()
