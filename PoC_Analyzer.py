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
import concurrent.futures
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeRemainingColumn, MofNCompleteColumn
import queue
import threading

console = Console()

class ConditionalBarColumn(BarColumn):
    def render(self, task):
        if task.fields.get("type") == "worker":
            return ""
        return super().render(task)

class ConditionalTextColumn(TextColumn):
    def render(self, task):
        if task.fields.get("type") == "worker":
            return "" 
        return super().render(task)

class ConditionalTimeColumn(TimeRemainingColumn):
    def render(self, task):
        if task.fields.get("type") == "worker":
            return "" 
        return super().render(task)

class ConditionalMofNColumn(MofNCompleteColumn):
    def render(self, task):
        if task.fields.get("type") == "worker":
            return "" 
        return super().render(task)

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

    # Mapping extensions to specific rule files
    RULE_MAPPING = {
        '.py': ['python.yaml', 'common.yaml'],
        '.js': ['js.yaml', 'common.yaml'],
        '.ts': ['js.yaml', 'common.yaml'],
        '.c': ['c.yaml', 'common.yaml'],
        '.cpp': ['c.yaml', 'common.yaml'],
        '.h': ['c.yaml', 'common.yaml'],
        '.php': ['php.yaml', 'common.yaml'],
        '.java': ['java.yaml', 'common.yaml'],
        '.go': ['go.yaml', 'common.yaml'],
        '.sh': ['shell.yaml', 'common.yaml'],
        '.bat': ['batch.yaml', 'common.yaml'],
        '.cmd': ['batch.yaml', 'common.yaml'],
        '.ps1': ['powershell.yaml', 'common.yaml'],
        '.psm1': ['powershell.yaml', 'common.yaml'],
    }

    def __init__(self, rule_config: str = "rules/", threshold: int = 100):
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
            console.print(f"[yellow][WARNING] Warning: Config '{rule_config}' not found locally or in rules/ dir.[/yellow]")

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
        
        # Determine which config to use
        config_args = []
        
        # If rule_config is a directory, try to be smart about which rules to apply
        if os.path.isdir(self.rule_config):
            _, ext = os.path.splitext(filepath)
            ext = ext.lower()
            
            if ext in self.RULE_MAPPING:
                # Use specific rules for this language
                for rule_file in self.RULE_MAPPING[ext]:
                    full_path = os.path.join(self.rule_config, rule_file)
                    if os.path.exists(full_path):
                        config_args.extend(["--config", full_path])
            
            # Fallback: if no mapping or files don't exist, use the whole directory
            if not config_args:
                config_args = ["--config", self.rule_config]
        else:
            # User provided a specific file, use it
            config_args = ["--config", self.rule_config]

        cmd = [
            "semgrep",
            *config_args,
            "--json",
            "--quiet", # Suppress progress bars
            "--jobs", "1",
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
    
    def scan_directory(self, directory: str, console: Console = None, max_workers: int = 8):
        """
        Scan directory using a Dashboard UI (Total Bar + Minimalist Worker Lines).
        """
        if console is None: console = Console()
        
        console.print(f"\n[bold cyan][DIRECTORY] Scanning Directory: {directory}[/bold cyan]")
        
        # 1. Prepare File List
        files_to_scan = []
        for root, _, files in os.walk(directory):
            for file in files:
                _, ext = os.path.splitext(file)
                if ext.lower() in self.valid_extensions:
                    files_to_scan.append(os.path.join(root, file))

        total_files = len(files_to_scan)
        if total_files == 0:
            console.print("[yellow]No supported files found in directory.[/yellow]")
            return []

        num_workers = min(max_workers, total_files)
        file_queue = queue.Queue()
        for f in files_to_scan:
            file_queue.put(f)

        console.print(f"[dim]Found {total_files} files. Starting {num_workers} worker threads.[/dim]\n")

        stats = {"MALICIOUS": 0, "SUSPICIOUS": 0, "SAFE": 0, "SKIPPED": 0}
        results = []
        stats_lock = threading.Lock()

        # 2. Setup Progress Dashboard
        progress = Progress(
            SpinnerColumn(),
            # This is the only column everyone will see: text description
            TextColumn("{task.description}"), 
            
            # The following columns are only shown for the Total task; Workers will leave these blank
            ConditionalBarColumn(bar_width=None),
            ConditionalTextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            ConditionalMofNColumn(),
            ConditionalTimeColumn(),
            
            console=console,
            transient=False
        )

        with progress:
            # (A) Create Total Progress Bar (no type="worker", so Bar is shown)
            main_task_id = progress.add_task("[bold green]Total Progress", total=total_files)
            
            # (B) Create Worker Status Lines (type="worker" to hide Bar)
            worker_tasks = []
            for i in range(num_workers):
                # Initial text set to Idle
                tid = progress.add_task(f"[dim]Worker {i+1}: Idle[/dim]", total=None, type="worker")
                worker_tasks.append(tid)

            # 3. Worker Logic
            def worker_logic(worker_idx, task_id):
                while True:
                    try:
                        filepath = file_queue.get_nowait()
                    except queue.Empty:
                        # No more work, hide or dim the line
                        progress.update(task_id, description=f"[dim]Worker {worker_idx+1}: Done[/dim]", visible=False)
                        break

                    # [UI Update] Only update text description, e.g., "Worker 1: Scanning bad.py..."
                    fname = os.path.basename(filepath)
                    if len(fname) > 30: fname = fname[:27] + "..."
                    
                    progress.update(task_id, description=f"[cyan]Worker {worker_idx+1}:[/cyan] Scanning {fname}")

                    try:
                        report = self.analyze(filepath)
                        
                        with stats_lock:
                            results.append(report)
                            verdict = report.get('verdict', 'SKIPPED')
                            stats[verdict] = stats.get(verdict, 0) + 1
                            
                            # Display alerts when threats are found
                            if verdict == "MALICIOUS":
                                progress.console.print(f"[bold red]!! DETECTED:[/bold red] {fname} (Score: {report['risk_score']})")
                            elif verdict == "SUSPICIOUS":
                                progress.console.print(f"[yellow]?! SUSPICIOUS:[/yellow] {fname}")

                    except Exception as e:
                        progress.console.print(f"[red]Error {fname}: {e}[/red]")
                    finally:
                        # Completed a file, advance total progress
                        progress.advance(main_task_id)
                        file_queue.task_done()

            # 4. Start Worker Threads
            with concurrent.futures.ThreadPoolExecutor(max_workers=num_workers) as executor:
                futures = [executor.submit(worker_logic, i, worker_tasks[i]) for i in range(num_workers)]
                concurrent.futures.wait(futures)

        # 5. Summary
        results.sort(key=lambda x: x['risk_score'], reverse=True)
        console.print("\n[bold][SUMMARY] Scan Results[/bold]")
        summary_table = Table(box=box.SIMPLE_HEAD, show_lines=False)
        summary_table.add_column("Verdict", justify="center", width=12)
        summary_table.add_column("Score", justify="right", width=6)
        summary_table.add_column("File Path", style="dim")
        summary_table.add_column("Threat", style="red")

        for res in results:
            v = res['verdict']
            if v == "SAFE": continue 

            if v == "MALICIOUS":
                color = "bold red"
            elif v == "SUSPICIOUS":
                color = "yellow"
            else:
                color = "green"
            
            top_threat = "-"
            if res['unique_findings']:
                top_finding = max(res['unique_findings'], key=lambda x: x['score'])
                top_threat = top_finding['category']

            summary_table.add_row(
                f"[{color}]{v}[/{color}]",
                str(res['risk_score']),
                res['filepath'],
                top_threat
            )
            
        console.print(summary_table)

        # Final Stats
        console.print(f"\n[dim]Scanned {total_files} files.[/dim]")
        if stats["MALICIOUS"] > 0:
            console.print(f"[bold red]Found {stats['MALICIOUS']} malicious files.[/bold red]")
        elif stats["SUSPICIOUS"] > 0:
            console.print(f"[bold yellow]Found {stats['SUSPICIOUS']} suspicious files.[/bold yellow]")
        else:
            console.print(f"[bold green]No threats found.[/bold green]")
        
        return results

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
            verdict_icon = "[MALICIOUS]"
        elif verdict == "SUSPICIOUS":
            verdict_color = "yellow"
            verdict_icon = "[SUSPICIOUS]"
        else:
            verdict_color = "green"
            verdict_icon = "[SAFE]"
        
        # Create summary panel
        summary = f"""[bold]File:[/bold] {report['filepath']}
[bold]Verdict:[/bold] [{verdict_color}]{verdict_icon} {verdict}[/{verdict_color}]
[bold]Risk Score:[/bold] {score}
[bold]Thresholds:[/bold] SAFE (0-{threshold//2-1}) | SUSPICIOUS ({threshold//2}-{threshold-1}) | MALICIOUS ({threshold}+)"""
        
        console.print(Panel(summary, title="[bold]Analysis Report[/bold]", border_style=verdict_color, box=box.ROUNDED))
        
        if report['findings']:
            console.print(f"\n[bold yellow][!] Risk Indicators Detected:[/bold yellow]\n")
            
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
                
                # Category tag mapping
                category_map = {
                    "backdoor": "[BACKDOOR]",
                    "rce": "[RCE]",
                    "obfuscation": "[OBFUSCATION]",
                    "file_manipulation": "[FILE_OPS]",
                    "credential_leak": "[CREDENTIALS]",
                    "deserialization": "[DESERIALIZATION]",
                    "code_injection": "[CODE_INJECTION]",
                    "network": "[NETWORK]",
                    "info_leak": "[INFO_LEAK]",
                    "abuse": "[ABUSE]",
                    "destruction": "[DESTRUCTION]",
                    "memory_corruption": "[MEMORY]",
                    "privilege_escalation": "[PRIV_ESC]",
                    "evasion": "[EVASION]",
                    "weak_crypto": "[WEAK_CRYPTO]",
                    "sql_injection": "[SQL_INJECTION]",
                    "xxe": "[XXE]",
                    "persistence": "[PERSISTENCE]",
                    "malware-dropper": "[DROPPER]",
                    "defense-evasion": "[DEF_EVASION]"
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
            console.print("\n[green][SAFE] No threats detected.[/green]\n")
    
    def print_directory_summary(self, reports: list[Dict[str, Any]], console: Console = None):
        """
        Print a summary for a directory scan.
        :param reports: A list of all file reports from the directory scan.
        :param console: Rich Console instance (optional).
        """
        if console is None:
            console = Console()

        total_files = len(reports)
        malicious_files = 0
        suspicious_files = 0
        safe_files = 0
        skipped_files = 0

        # First, print individual reports for files with risk
        console.print("\n[bold underline]Detailed File Reports:[/bold underline]\n")
        has_findings = False
        for report in reports:
            if report['verdict'] == "SKIPPED":
                skipped_files += 1
            elif report['risk_score'] > 0:
                self.print_report(report, console)
                has_findings = True
                if report['verdict'] == "MALICIOUS":
                    malicious_files += 1
                elif report['verdict'] == "SUSPICIOUS":
                    suspicious_files += 1
            else:
                safe_files += 1
        
        if not has_findings:
            console.print("[green][SAFE] No individual threats to report.[/green]\n")

        # Then, print a final directory summary
        summary = f"""[bold]Total Files Scanned:[/bold] {total_files}
[bold green]SAFE Files:[/bold green] {safe_files}
[bold yellow]SUSPICIOUS Files:[/bold yellow] {suspicious_files}
[bold red]MALICIOUS Files:[/bold red] {malicious_files}
[bold dim]SKIPPED Files (Unsupported Ext):[/bold dim] {skipped_files}"""

        console.print(Panel(
            summary,
            title="[bold]Directory Scan Summary[/bold]",
            border_style="blue",
            box=box.ROUNDED
        ))
    
    def scan_and_report(self, filepath: str, console: Console = None):
        """
        Convenience method to scan a file and print the report.
        
        :param filepath: Path to the file to analyze
        :param console: Rich Console instance (optional)
        """
        if console is None:
            console = Console()
        
        console.print(f"\n[cyan][SCAN] Scanning {filepath}...[/cyan]\n")
        
        try:
            if os.path.isdir(filepath):
                return self.scan_directory(filepath, console)
            else:
                report = self.analyze(filepath)
                self.print_report(report, console)
                return report
        except Exception as e:
            console.print(f"[bold red][ERROR] Scan failed: {e}[/bold red]")
            raise

def parse_arguments():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="PoC Analyzer - Static Analysis Engine for Proof-of-Concept scripts",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python PoC_Analyzer.py test_PoC/malicious_test.js
  python PoC_Analyzer.py -c python.yaml -t 120 test_PoC/malicious_test.py
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
        default=100,
        help='Risk score threshold for MALICIOUS verdict (default: 100)'
    )
    
    parser.add_argument(
        '--all-rules',
        action='store_true',
        help='Force scan with ALL rules (ignore extension mapping). Useful for deep inspection.'
    )
    
    return parser.parse_args()

if __name__ == "__main__":
    # Parse command-line arguments
    args = parse_arguments()
    
    # Check if file exists
    if not os.path.exists(args.filepath):
        console.print(f"[bold red][ERROR] Error: File '{args.filepath}' not found.[/bold red]")
        exit(1)
    
    config_path = args.config if args.config else "rules/"

    # Initialize the engine
    engine = PoCAnalyzer(rule_config=config_path, threshold=args.threshold)
    
    # If --all-rules is set, clear the mapping to force full scan
    if args.all_rules:
        engine.RULE_MAPPING = {}
        console.print("[yellow][WARNING] Deep Scan Mode: Using ALL rules for analysis.[/yellow]")

    # Scan and print report
    try:
        engine.scan_and_report(args.filepath, console)
    except Exception:
        exit(1)