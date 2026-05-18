#!/usr/bin/env python3
"""
MCP Security Scanner v2
Scans MCP servers for common vulnerability patterns in Python, JavaScript, and TypeScript.
"""

import os
import re
import sys
import json
from pathlib import Path

class MCPSecurityScanner:
    def __init__(self, target_path):
        self.target_path = Path(target_path)
        self.findings = []
        self.files_scanned = 0
        
        # Vulnerability patterns - language specific
        self.patterns = {
            # JavaScript/TypeScript patterns
            "js": {
                "path_traversal": [
                    (r"path\.resolve\([^)]*\+", "Potential path traversal via string concatenation"),
                    (r"path\.join\([^)]*\+", "Potential path traversal via string concatenation"),
                    (r"fs\.readFile\([^)]*\+", "Potential path traversal in file read"),
                    (r"fs\.writeFile\([^)]*\+", "Potential path traversal in file write"),
                    (r"fs\.readFileSync\([^)]*\+", "Potential path traversal in file read"),
                    (r"fs\.writeFileSync\([^)]*\+", "Potential path traversal in file write"),
                ],
                "command_injection": [
                    (r"exec\([^)]*\+", "Potential command injection via exec()"),
                    (r"execSync\([^)]*\+", "Potential command injection via execSync()"),
                    (r"spawn\([^)]*\+", "Potential command injection via spawn()"),
                    (r"child_process", "Uses child_process module"),
                ],
                "ssrf": [
                    (r"fetch\([^)]*\+", "Potential SSRF via fetch()"),
                    (r"axios\([^)]*\+", "Potential SSRF via axios()"),
                    (r"http\.request\([^)]*\+", "Potential SSRF via http.request()"),
                ],
            },
            # Python patterns
            "py": {
                "path_traversal": [
                    (r"os\.path\.join\([^)]*\)", "Potential path traversal in os.path.join"),
                    (r"open\([^)]*\)", "Potential path traversal in file open"),
                    (r"os\.makedirs\([^)]*\)", "Potential path traversal in directory creation"),
                    (r"shutil\.copy\([^)]*\)", "Potential path traversal in file copy"),
                    (r"shutil\.move\([^)]*\)", "Potential path traversal in file move"),
                ],
                "command_injection": [
                    (r"os\.system\(", "Potential command injection via os.system()"),
                    (r"subprocess\.", "Uses subprocess module"),
                    (r"subprocess\.run\(", "Potential command injection via subprocess.run()"),
                    (r"subprocess\.Popen\(", "Potential command injection via subprocess.Popen()"),
                    (r"os\.popen\(", "Potential command injection via os.popen()"),
                ],
                "deserialization": [
                    (r"pickle\.load", "Unsafe deserialization via pickle"),
                    (r"pickle\.loads", "Unsafe deserialization via pickle.loads"),
                    (r"yaml\.load\(", "Unsafe YAML deserialization"),
                ],
                "ssrf": [
                    (r"requests\.get\([^)]*\)", "Potential SSRF via requests.get()"),
                    (r"requests\.post\([^)]*\)", "Potential SSRF via requests.post()"),
                    (r"urllib\.request\.", "Potential SSRF via urllib.request"),
                ],
            }
        }
    
    def get_file_type(self, file_path):
        ext = file_path.suffix
        if ext in ('.ts', '.js', '.tsx', '.jsx'):
            return 'js'
        elif ext == '.py':
            return 'py'
        return None
    
    def scan_file(self, file_path):
        file_type = self.get_file_type(file_path)
        if not file_type:
            return
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
            
            patterns = self.patterns.get(file_type, {})
            for vuln_type, type_patterns in patterns.items():
                for pattern, description in type_patterns:
                    for i, line in enumerate(lines, 1):
                        if re.search(pattern, line, re.IGNORECASE):
                            # Skip test files and node_modules
                            if 'test' in str(file_path).lower() or 'node_modules' in str(file_path):
                                continue
                            self.findings.append({
                                "file": str(file_path.relative_to(self.target_path)),
                                "line": i,
                                "type": vuln_type,
                                "description": description,
                                "code": line.strip()[:100],
                                "severity": self._get_severity(vuln_type)
                            })
            
            self.files_scanned += 1
        except Exception as e:
            pass
    
    def scan_directory(self):
        extensions = {'.ts', '.js', '.tsx', '.jsx', '.py'}
        for file_path in self.target_path.rglob('*'):
            if file_path.is_file() and file_path.suffix in extensions:
                if 'node_modules' in str(file_path) or '__pycache__' in str(file_path):
                    continue
                self.scan_file(file_path)
    
    def _get_severity(self, vuln_type):
        severity_map = {
            "command_injection": "CRITICAL",
            "path_traversal": "HIGH",
            "deserialization": "HIGH",
            "ssrf": "HIGH",
        }
        return severity_map.get(vuln_type, "MEDIUM")
    
    def generate_report(self):
        report = {
            "target": str(self.target_path),
            "files_scanned": self.files_scanned,
            "total_findings": len(self.findings),
            "severity_counts": {},
            "findings": self.findings
        }
        for finding in self.findings:
            severity = finding["severity"]
            report["severity_counts"][severity] = report["severity_counts"].get(severity, 0) + 1
        return report
    
    def print_report(self):
        report = self.generate_report()
        print(f"\n{'='*60}")
        print(f"MCP SECURITY AUDIT REPORT v2")
        print(f"{'='*60}")
        print(f"Target: {report['target']}")
        print(f"Files Scanned: {report['files_scanned']}")
        print(f"Total Findings: {report['total_findings']}")
        print(f"\nSeverity Breakdown:")
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            count = report['severity_counts'].get(severity, 0)
            if count > 0:
                print(f"  {severity}: {count}")
        
        if report['findings']:
            print(f"\n{'='*60}")
            print(f"FINDINGS")
            print(f"{'='*60}")
            for i, finding in enumerate(report['findings'], 1):
                print(f"\n[{finding['severity']}] Finding #{i}")
                print(f"  Type: {finding['type']}")
                print(f"  File: {finding['file']}:{finding['line']}")
                print(f"  Description: {finding['description']}")
                print(f"  Code: {finding['code']}")
        else:
            print(f"\nNo vulnerabilities found.")
        print(f"\n{'='*60}")
        return report

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python mcp-scanner-v2.py <path-to-mcp-server>")
        sys.exit(1)
    
    target = sys.argv[1]
    if not os.path.exists(target):
        print(f"Error: {target} does not exist")
        sys.exit(1)
    
    scanner = MCPSecurityScanner(target)
    print(f"Scanning {target}...")
    scanner.scan_directory()
    report = scanner.print_report()
    
    report_path = Path(target) / "security-audit-report-v2.json"
    with open(report_path, 'w') as f:
        json.dump(report, f, indent=2)
    print(f"\nReport saved to: {report_path}")
