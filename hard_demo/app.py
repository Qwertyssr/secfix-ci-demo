"""Advanced, intentionally vulnerable module used to STRESS-TEST secfix.

It deliberately mixes:
  * cases the deterministic rule engine can fix (md5 hash, shell=True), and
  * hard cases it must safely ESCALATE (XXE, SSRF, pickle, eval, path traversal,
    hardcoded secret, f-string SQL injection) rather than guess.
Only parsed as text by the fixers, so third-party imports are unnecessary.
"""
import hashlib
import pickle
import sqlite3
import subprocess
import xml.etree.ElementTree as ET


def simple_hash(data: str) -> str:
    # EASY (Fortify: Weak Cryptographic Hash) -> rule rewrites md5 -> sha256
    return hashlib.md5(data.encode()).hexdigest()


def run_job(job_name: str) -> int:
    # EASY (Fortify: Command Injection) -> rule removes the dangerous shell flag
    cmd = "python worker.py --job " + job_name
    return subprocess.call(cmd, shell=True)


def read_upload(base_dir: str, name: str) -> bytes:
    # HARD (Fortify: Path Manipulation) -> escalate (needs canonicalization)
    with open(base_dir + "/" + name, "rb") as fh:
        return fh.read()


def load_session(blob: bytes):
    # HARD (Fortify: Insecure Deserialization) -> escalate (pickle, not yaml)
    return pickle.loads(blob)


def find_user(conn: sqlite3.Connection, name: str):
    # HARD (Fortify: SQL Injection) -> escalate (f-string form, not concat)
    return conn.execute(f"SELECT * FROM users WHERE name = '{name}'").fetchone()


def compute(expr: str):
    # HARD (Fortify: Dynamic Code Evaluation) -> escalate (eval)
    return eval(expr)


def parse_document(payload: bytes):
    # HARD (Fortify: XML External Entity Injection) -> escalate (XXE)
    return ET.fromstring(payload)


# HARD (Fortify: Hardcoded Password) -> escalate + flag for rotation
API_KEY = "AKIA1234567890EXAMPLE"
