import json
import subprocess
import shutil
import os
import argparse
from typing import Dict, Any, Set
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

console = Console()

class PoCAnalyzer:
    """
    Static Analysis Engine for Proof-of-Concept (PoC) scripts.
    Uses Semgrep rules to calculate risk scores based on heuristic patterns.
    """

    # Default supported extensions
    DEFAULT_EXTENSIONS = {
        '.py',              # Python
        '.js', '.ts',       # JavaScript / Node.js
        '.c', '.cpp', '.h', # C / C++
        '.php',             # PHP
        '.java',            # Java
        '.go',              # Go
        '.sh',              # Shell
        '.cmd', '.bat',     # Windows Batch
        '.ps1', '.psm1'     # PowerShell
    }

    def __init__(self, rule_config: str = "rules/", threshold: int = 150):
        """
        Initialize the analyzer.
        
        :param rule_config: Path to the Semgrep YAML configuration file.
        :param threshold: The score above which a PoC is considered 'MALICIOUS'.
        """
        # Smart path handling: add 'rules/' prefix only if not already present
        if os.path.exists(rule_config):
            self.rule_config = rule_config
        elif os.path.exists(os.path.join("rules", rule_config)):
            self.rule_config = os.path.join("rules", rule_config)
        else:
            self.rule_config = rule_config
            console.print(f"[yellow]⚠️ Warning: Config '{rule_config}' not found locally or in rules/ dir.[/yellow]")

        self.threshold = threshold
        self.valid_extensions: Set[str] = self.DEFAULT_EXTENSIONS
        
        # Pre-check: Ensure semgrep is installed
        if not shutil.which("semgrep"):
            raise EnvironmentError("Semgrep is not installed or not in PATH.")
    
    def set_extensions(self, extensions: Set[str]):
        """Allow dynamic overriding of supported extensions."""
        self.valid_extensions = extensions

    def _run_semgrep(self, filepath: str) -> Dict[str, Any]:
        """Internal method to execute the semgrep CLI process."""
        cmd = [
            "semgrep",
            "--config", self.rule_config,
            "--json",
            "--quiet", # Suppress progress bars
            filepath
        ]

        try:
            result = subprocess.run(
                cmd, 
                capture_output=True, 
                text=True, 
                check=False  # Don't raise error on exit code 1 (semgrep returns 1 on findings)
            )
            
            if not result.stdout.strip():
                return {"results": []}
                
            return json.loads(result.stdout)
            
        except json.JSONDecodeError:
            print(f"[!] Error: Failed to parse Semgrep output. Raw: {result.stderr}")
            return {"results": []}
        except Exception as e:
            print(f"[!] System Error: {str(e)}")
            return {"results": []}

    @staticmethod
    def _calculate_risk(findings: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process raw findings and calculate total risk score.
        Uses deduplication: same line + same category -> only count highest score.
        """
        # Group findings by (line, category) to avoid duplicate scoring
        line_category_map = {}
        all_findings = []

        for item in findings.get("results", []):
            # Extract metadata safely
            metadata = item.get("extra", {}).get("metadata", {})
            rule_id = item.get("check_id")
            message = item.get("extra", {}).get("message")
            line = item.get("start", {}).get("line")
            
            # Default to 0 if risk_score is missing in YAML
            score = metadata.get("risk_score", 0)
            category = metadata.get("category", "unknown")

            finding = {
                "rule": rule_id,
                "score": score,
                "category": category,
                "message": message,
                "line": line
            }
            
            all_findings.append(finding)
            
            # Deduplication key: (line_number, category)
            key = (line, category)
            
            if key not in line_category_map:
                line_category_map[key] = finding
            else:
                # Keep the one with higher score
                if score > line_category_map[key]["score"]:
                    line_category_map[key] = finding

        # Calculate total score from deduplicated findings
        total_score = sum(f["score"] for f in line_category_map.values())

        return {
            "total_score": total_score,
            "details": all_findings,  # Return all findings for transparency
            "unique_findings": list(line_category_map.values())  # Deduplicated list
        }

    def analyze(self, filepath: str) -> Dict[str, Any]:
        """
        Public interface to scan a file.
        Returns a full report dictionary.
        """
        _, ext = os.path.splitext(filepath)
        if ext.lower() not in self.valid_extensions:
            return {
                "filepath": filepath,
                "verdict": "SKIPPED",
                "risk_score": 0,
                "threshold": self.threshold,
                "findings": [],
                "unique_findings": [],
                "reason": f"Unsupported extension: {ext}"
            }


        # 1. Static Scan
        raw_data = self._run_semgrep(filepath)
        
        # 2. Risk Calculation
        analysis = self._calculate_risk(raw_data)
        score = analysis["total_score"]
        
        # 3. Final Verdict
        if score >= self.threshold:
            verdict = "MALICIOUS"
        elif score >= (self.threshold / 2):
            verdict = "SUSPICIOUS"
        else:
            verdict = "SAFE"

        return {
            "filepath": filepath,
            "verdict": verdict,
            "risk_score": score,
            "threshold": self.threshold,
            "findings": analysis["details"],
            "unique_findings": analysis["unique_findings"]
        }
    
    def print_report(self, report: Dict[str, Any], console: Console = None):
        """
        Print a formatted analysis report using Rich.
        
        :param report: The report dictionary from analyze()
        :param console: Rich Console instance (optional)
        """
        if console is None:
            console = Console()
        
        # Determine verdict color and icon
        verdict = report['verdict']
        score = report['risk_score']
        threshold = report['threshold']
        
        if verdict == "MALICIOUS":
            verdict_color = "red"
            verdict_icon = "🚨"
        elif verdict == "SUSPICIOUS":
            verdict_color = "yellow"
            verdict_icon = "⚠️"
        else:
            verdict_color = "green"
            verdict_icon = "✅"
        
        # Create summary panel
        summary = f"""[bold]File:[/bold] {report['filepath']}
[bold]Verdict:[/bold] [{verdict_color}]{verdict_icon} {verdict}[/{verdict_color}]
[bold]Risk Score:[/bold] {score}
[bold]Thresholds:[/bold] SAFE (0-{threshold//2-1}) | SUSPICIOUS ({threshold//2}-{threshold-1}) | MALICIOUS ({threshold}+)"""
        
        console.print(Panel(summary, title="[bold]Analysis Report[/bold]", border_style=verdict_color, box=box.ROUNDED))
        
        if report['findings']:
            console.print(f"\n[bold yellow]⚠️  Risk Indicators Detected:[/bold yellow]\n")
            
            # Create findings table
            table = Table(show_header=True, header_style="bold magenta", box=box.SIMPLE)
            table.add_column("Line", style="cyan", width=6)
            table.add_column("Category", style="blue", width=18)
            table.add_column("Score", justify="right", width=6)
            table.add_column("Rule ID", style="dim")
            table.add_column("Message")
            
            for f in report['findings']:
                # Color code by score
                if f['score'] >= 80:
                    score_color = "red"
                elif f['score'] >= 50:
                    score_color = "yellow"
                else:
                    score_color = "green"
                
                # Category emoji
                category_map = {
                    "backdoor": "🔴 backdoor",
                    "rce": "💣 rce",
                    "obfuscation": "🎭 obfuscation",
                    "file_manipulation": "📁 file_ops",
                    "credential_leak": "🔑 credentials",
                    "deserialization": "⚠️ deserialize",
                    "code_injection": "💉 code_inject",
                    "network": "🌐 network",
                    "info_leak": "ℹ️ info_leak",
                    "abuse": "🚫 abuse",
                    "memory_corruption": "💥 memory",
                    "privilege_escalation": "👑 priv_esc",
                    "evasion": "🥷 evasion",
                    "weak_crypto": "🔓 weak_crypto",
                    "sql_injection": "💉 sql_inject",
                    "xxe": "📄 xxe"
                }
                category_display = category_map.get(f['category'], f['category'])
                
                table.add_row(
                    str(f['line']),
                    category_display,
                    f"[{score_color}]{f['score']}[/{score_color}]",
                    f['rule'].replace('rules.', ''),
                    f['message'].replace('[JS] ', '').replace('[Python] ', '').replace('[PHP] ', '')
                )
            
            console.print(table)
            
            # Scoring info
            unique_count = len(report.get('unique_findings', []))
            total_count = len(report['findings'])
            dedup_info = f"[dim]Found {total_count} total detections, deduplicated to {unique_count} unique threats.[/dim]"
            console.print(f"\n{dedup_info}\n")
        else:
            console.print("\n[green]✅ No threats detected.[/green]\n")
    
    def scan_and_report(self, filepath: str, console: Console = None):
        """
        Convenience method to scan a file and print the report.
        
        :param filepath: Path to the file to analyze
        :param console: Rich Console instance (optional)
        """
        if console is None:
            console = Console()
        
        console.print(f"\n[cyan]🔍 Scanning {filepath}...[/cyan]\n")
        
        try:
            report = self.analyze(filepath)
            self.print_report(report, console)
            return report
        except Exception as e:
            console.print(f"[bold red]❌ Scan failed: {e}[/bold red]")
            raise

def parse_arguments():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="PoC Analyzer - Static Analysis Engine for Proof-of-Concept scripts",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 PoC_Analyzer.py test_PoC/malicious_test.js
  python3 PoC_Analyzer.py -c python.yaml -t 120 suspicious_script.py
        """
    )
    
    parser.add_argument(
        'filepath',
        help='Path to the file to analyze'
    )
    
    parser.add_argument(
        '-c', '--config',
        default=None, 
        help='Semgrep rule config file/dir. Defaults to scanning "rules/" directory.'
    )
    
    parser.add_argument(
        '-t', '--threshold',
        type=int,
        default=150,
        help='Risk score threshold for MALICIOUS verdict (default: 150)'
    )
    
    return parser.parse_args()

if __name__ == "__main__":
    # Parse command-line arguments
    args = parse_arguments()
    
    # Check if file exists
    if not os.path.exists(args.filepath):
        console.print(f"[bold red]❌ Error: File '{args.filepath}' not found.[/bold red]")
        exit(1)
    
    config_path = args.config if args.config else "rules/"
    # Initialize the engine
    engine = PoCAnalyzer(rule_config=config_path, threshold=args.threshold)

    # Scan and print report
    try:
        engine.scan_and_report(args.filepath, console)
    except Exception:
        exit(1)