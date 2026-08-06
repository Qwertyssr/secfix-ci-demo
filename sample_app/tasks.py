"""Background task helpers.

NOTE: intentionally vulnerable for the security-fix demo.
Fortify flags subprocess with shell=True as 'Command Injection'.
"""
import subprocess


def run_report(report_name: str) -> int:
    # VULN (Fortify: Command Injection) -> shell=True with interpolated input
    cmd = ["python", "generate_report.py", "--name", report_name]
    return subprocess.call(cmd)
