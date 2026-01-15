import json
import subprocess
import shutil
import os
import argparse
from typing import Dict, Any, Set
from rich.console import Console
from rich.table import Table, Column
from rich.panel import Panel
from rich import box
import concurrent.futures
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeRemainingColumn, MofNCompleteColumn
import queue
import threading
from update_blacklist import update_blacklist_file

console = Console()

# Category display mapping and High-Level Grouping
CATEGORY_MAP = {
    # 1. Execution Control / Access
    "code_injection": "CODE_INJECTION",
    "indirect-execution": "INDIRECT_EXECUTION",
    "deserialization": "DESERIALIZATION",
    "privilege_escalation": "PRIV_ESC",

    # 2. Persistence / Access
    "backdoor": "BACKDOOR",
    "persistence": "PERSISTENCE",
    
    # 3. Delivery / Infection
    "malware-dropper": "DROPPER",
    
    # 4. Defense Evasion
    "obfuscation": "OBFUSCATION",
    "defense-evasion": "DEF_EVASION",
    "evasion": "EVASION",

    # 5. File System Operations
    "file_manipulation": "FILE_OPS",
    "destruction": "DESTRUCTION",
    
    # 6. Network Communication
    "malicious-domain": "MALICIOUS_DOMAIN",
    "network": "NETWORK",
    
    # 7. Information Risk
    "credential_leak": "CREDENTIALS",

    # 8. Abuse Behavior
    "abuse": "ABUSE", # Spam, Crypto-mining
}

# High-Level Categories for Executive Summary
THREAT_GROUPS = {
    "Execution Control": ["code_injection", "indirect-execution", "deserialization", "privilege_escalation"],
    "Persistence Access": ["backdoor", "persistence"],
    "Delivery Infection": ["malware-dropper"],
    "Defense Evasion": ["obfuscation", "defense-evasion", "evasion"],
    "File System Ops": ["file_manipulation", "destruction"],
    "Network Communication": ["network", "malicious-domain"],
    "Information Risk": ["credential_leak"],
    "Abuse Behavior": ["abuse"],
}

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

    def _calculate_risk(self, findings: Dict[str, Any]) -> Dict[str, Any]:
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

    def _check_blacklist(self, filepath: str) -> list[Dict[str, Any]]:
        """
        Check file content against blacklist.txt using simple regex.
        Returns a list of 'finding' dicts if matches are found.
        """
        blacklist_path = os.path.join(os.path.dirname(self.rule_config), "data", "blacklist.txt")
        # Fallback if rule_config is a file not dir
        if not os.path.exists(blacklist_path):
             blacklist_path = os.path.join("rules", "data", "blacklist.txt")
             
        if not os.path.exists(blacklist_path):
            return []

        findings = []
        try:
            with open(blacklist_path, "r") as f:
                patterns = [line.strip() for line in f if line.strip() and not line.startswith("#")]
            
            if not patterns:
                return []
                
            # Compile regex pattern (OR logic)
            # Escape dots is handled by user in blacklist file or assumed raw
            # Ideally user provides regex-ready strings, or we escape them.
            # For simplicity, we assume the blacklist contains regex fragments.
            full_pattern = "|".join(patterns)
            import re
            regex = re.compile(full_pattern, re.IGNORECASE)

            with open(filepath, "r", errors="ignore") as f:
                for i, line in enumerate(f, 1):
                    match = regex.search(line)
                    if match:
                        findings.append({
                            "rule": "custom-blacklist-match",
                            "score": 100,
                            "category": "malicious-domain",
                            "message": f"[Critical] Blacklisted IP/Domain detected: '{match.group(0)}'",
                            "line": i
                        })
        except Exception as e:
            # console.print(f"[red]Blacklist check error: {e}[/red]")
            pass
            
        return findings

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


        # 1. Static Scan (Semgrep)
        raw_data = self._run_semgrep(filepath)
        
        # 2. Risk Calculation (Semgrep)
        analysis = self._calculate_risk(raw_data)
        
        # 3. Dynamic Blacklist Check (Python)
        blacklist_findings = self._check_blacklist(filepath)
        
        # Merge Semgrep findings with Blacklist findings
        final_findings = analysis["details"] + blacklist_findings
        
        # Re-deduplicate with the new findings included
        # We reuse the logic from _calculate_risk but apply it to the merged list locally
        line_category_map = {}
        # Pre-fill map with existing unique findings
        for f in analysis["unique_findings"]:
             line_category_map[(f['line'], f['category'])] = f
        
        # Add blacklist findings (they likely have score 100, so they override)
        for f in blacklist_findings:
            key = (f['line'], f['category'])
            if key not in line_category_map or f['score'] > line_category_map[key]['score']:
                line_category_map[key] = f
        
        unique_findings = list(line_category_map.values())
        total_score = sum(f["score"] for f in unique_findings)
        
        # 4. Final Verdict
        if total_score >= self.threshold:
            verdict = "MALICIOUS"
        elif total_score > 0:
            verdict = "SUSPICIOUS"
        else:
            verdict = "SAFE"

        return {
            "filepath": filepath,
            "verdict": verdict,
            "risk_score": total_score,
            "threshold": self.threshold,
            "findings": final_findings,
            "unique_findings": unique_findings
        }
    
    def scan_directory(self, directory: str, console: Console = None, max_workers: int = 4) -> list[Dict[str, Any]]:
        """
        Scan directory using a Dashboard UI (Total Bar + Minimalist Worker Lines).
        """
        if console is None: console = Console()
        
        # Safety Check: Cap workers at CPU count to prevent freezing
        # Each worker spawns a semgrep subprocess which is CPU-intensive
        try:
            sys_cores = os.cpu_count() or 4
        except Exception:
            sys_cores = 4

        if max_workers > sys_cores:
            console.print(f"[yellow][!] Limiting workers to {sys_cores} (System Cores) to prevent CPU saturation.[/yellow]")
            console.print(f"[dim]    (Requested: {max_workers}, Available Cores: {sys_cores})[/dim]")
            max_workers = sys_cores

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
            TextColumn(
                "{task.description}", 
                table_column=Column(width=35, overflow="ellipsis", no_wrap=True)
            ),
            
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
        self.print_directory_summary(results, stats, total_files, directory, console)
        
        return results

    def print_directory_summary(self, results: list, stats: dict, total_files: int, directory: str, console: Console):
        """
        Print the summary dashboard for a directory scan.
        """
        results.sort(key=lambda x: x['risk_score'], reverse=True)
        
        # Show all files with score > 0, even if SAFE
        threat_results = [r for r in results if r['risk_score'] > 0]

        if threat_results:
            summary_table = Table(box=box.SIMPLE_HEAD, show_lines=False, expand=True)
            summary_table.add_column("Verdict", justify="center", no_wrap=True)
            summary_table.add_column("Score", justify="center", no_wrap=True)
            summary_table.add_column("File Path", style="dim", ratio=1)
            summary_table.add_column("Threat", style="red", no_wrap=True)
            summary_table.add_column("Line", style="dim", justify="center", no_wrap=True)

            for res in threat_results:
                v = res['verdict']
                
                if v == "MALICIOUS":
                    color = "bold red"
                elif v == "SUSPICIOUS":
                    color = "yellow"
                else:
                    color = "green"
                
                top_threat = "-"
                line_info = "-"
                
                if res['unique_findings']:
                    top_finding = max(res['unique_findings'], key=lambda x: x['score'])
                    top_threat = CATEGORY_MAP.get(top_finding['category'], top_finding['category'])
                    line_info = str(top_finding['line'])

                # Show path relative to the scanned directory
                display_path = os.path.relpath(res['filepath'], directory)

                summary_table.add_row(
                    f"[{color}]{v}[/{color}]",
                    str(res['risk_score']),
                    display_path,
                    top_threat,
                    line_info
                )
            
            console.print(Panel(
                summary_table,
                title="[bold]Suspicious & Malicious Files[/bold]",
                border_style="red",
                box=box.ROUNDED
            ))

        # Final Stats Panel
        summary_text = f"""[bold]Total Files Scanned:[/bold] {total_files}
[bold green]SAFE Files:[/bold green] {stats.get('SAFE', 0)}
[bold yellow]SUSPICIOUS Files:[/bold yellow] {stats.get('SUSPICIOUS', 0)}
[bold red]MALICIOUS Files:[/bold red] {stats.get('MALICIOUS', 0)}
[bold dim]SKIPPED Files (Unsupported Ext):[/bold dim] {stats.get('SKIPPED', 0)}"""

        console.print(Panel(
            summary_text,
            title="[bold]Directory Scan Summary[/bold]",
            border_style="blue",
            box=box.ROUNDED
        ))

        # Threat Group Summary
        # Flatten all unique categories found across all malicious/suspicious files
        detected_categories = set()
        for res in threat_results:
            for finding in res.get('unique_findings', []):
                detected_categories.add(finding['category'])
        
        if detected_categories:
            # Create a table for groups
            group_table = Table(box=box.SIMPLE, show_header=True, expand=True)
            group_table.add_column("Threat Group", style="bold", no_wrap=True)
            group_table.add_column("Status", justify="center", no_wrap=True)
            group_table.add_column("Detected Types", style="dim", ratio=1)

            for group_name, subtypes in THREAT_GROUPS.items():
                # Check intersection between this group's subtypes and what we found
                found_in_group = detected_categories.intersection(set(subtypes))
                
                if found_in_group:
                    status = "[red]DETECTED[/red]"
                    # Convert raw category to display name if possible, or keep raw
                    display_types = ", ".join([CATEGORY_MAP.get(c, c).replace('[', '').replace(']', '') for c in found_in_group])
                else:
                    status = "[green]CLEAN[/green]"
                    display_types = "-"
                
                group_table.add_row(group_name, status, display_types)
            
            console.print(Panel(
                group_table,
                title="[bold]PoC Scan Result Summary[/bold]",
                border_style="cyan",
                box=box.ROUNDED
            ))

        console.print("\n[dim]Tip: For detailed analysis, run the scanner on a specific file directly.[/dim]\n")

    def print_single_file_report(self, report: Dict[str, Any], console: Console = None):
        """
        Print a formatted analysis report for a single file using Rich.
        
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
        elif verdict == "SUSPICIOUS":
            verdict_color = "yellow"
        else:
            verdict_color = "green"
        
        # Create summary panel
        summary = f"""[bold]File:[/bold] {report['filepath']}
[bold]Verdict:[/bold] [{verdict_color}]{verdict}[/{verdict_color}]
[bold]Risk Score:[/bold] {score}
[bold]Thresholds:[/bold] SAFE (0) | SUSPICIOUS (1-{threshold-1}) | MALICIOUS ({threshold}+)"""
        
        console.print(Panel(summary, title="[bold]Analysis Report[/bold]", border_style=verdict_color, box=box.ROUNDED))
        
        if report['findings']:
            # Create findings table
            table = Table(show_header=True, header_style="bold magenta", box=box.SIMPLE, expand=True)
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
                category_display = CATEGORY_MAP.get(f['category'], f['category'])
                
                table.add_row(
                    str(f['line']),
                    category_display,
                    f"[{score_color}]{f['score']}[/{score_color}]",
                    f['rule'].replace('rules.', ''),
                    f['message'].replace('[JS] ', '').replace('[Python] ', '').replace('[PHP] ', '')
                )
            
            console.print(Panel(
                table,
                title="[bold yellow]Detailed Threat Analysis[/bold yellow]",
                border_style="yellow",
                box=box.ROUNDED
            ))
            
            # Scoring info
            unique_count = len(report.get('unique_findings', []))
            total_count = len(report['findings'])
            dedup_info = f"[dim]Found {total_count} total detections, deduplicated to {unique_count} unique threats.[/dim]"
            console.print(f"\n{dedup_info}\n")
        else:
            console.print("\n[green][SAFE] No threats detected.[/green]\n")
    
    def scan_and_report(self, filepath: str, console: Console = None, max_workers: int = 8):
        """
        Convenience method to scan a file and print the report.
        Uses a spinner animation for better UX.
        
        :param filepath: Path to the file to analyze
        :param console: Rich Console instance (optional)
        :param max_workers: Number of worker threads for directory scanning
        """
        if console is None:
            console = Console()
        
        try:
            if os.path.isdir(filepath):
                return self.scan_directory(filepath, console, max_workers=max_workers)
            else:
                report = None
                with console.status(f"[bold cyan]Scanning {filepath}...[/bold cyan]", spinner="dots"):
                    report = self.analyze(filepath)
                
                self.print_single_file_report(report, console)
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
  python PoC_Analyzer.py --all-rules test_PoC/malicious_test.php
  python PoC_Analyzer.py -w 4 test_PoC/
  python PoC_Analyzer.py -m 1000 test_PoC/malicious_test.py
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

    parser.add_argument(
        '-w', '--workers',
        type=int,
        default=4,
        help='Number of worker threads for directory scanning (default: 4)'
    )

    parser.add_argument(
        '-m', '--max-entries',
        type=int,
        default=500,
        help='Maximum number of entries to fetch for blacklist update (default: 500)'
    )

    parser.add_argument(
        '-v', '--version',
        action='version',
        version='PoC Analyzer 1.0.0',
        help='Show program version and exit'
    )
    
    return parser.parse_args()

if __name__ == "__main__":
    # Parse command-line arguments
    args = parse_arguments()
    
    # Check if file exists
    if not os.path.exists(args.filepath):
        console.print(f"[bold red][ERROR] Error: File '{args.filepath}' not found.[/bold red]")
        exit(1)
    
    # Update blacklist before scanning
    update_blacklist_file(max_entries=args.max_entries)
    
    config_path = args.config if args.config else "rules/"

    # Initialize the engine
    engine = PoCAnalyzer(rule_config=config_path, threshold=args.threshold)
    
    # If --all-rules is set, clear the mapping to force full scan
    if args.all_rules:
        engine.RULE_MAPPING = {}
        console.print("[yellow][WARNING] Deep Scan Mode: Using ALL rules for analysis.[/yellow]")

    # Scan and print report
    try:
        engine.scan_and_report(args.filepath, console, max_workers=args.workers)
    except Exception:
        exit(1)