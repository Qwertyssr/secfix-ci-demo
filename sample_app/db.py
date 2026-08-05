"""Tiny data-access layer over sqlite3.

NOTE: intentionally vulnerable for the security-fix demo.
Fortify flags the string-built SQL below as 'SQL Injection'.
"""
import sqlite3


def find_user(conn: sqlite3.Connection, username: str):
    cur = conn.cursor()
    # VULN (Fortify: SQL Injection) -> string-concatenated query
    cur.execute("SELECT id, username FROM users WHERE username = ?", (username,))
    return cur.fetchone()
