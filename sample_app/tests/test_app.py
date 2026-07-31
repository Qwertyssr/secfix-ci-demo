"""Behavioural tests for the sample app.

These must keep passing AFTER the security-fix agent applies its patches —
that is how the agent's Validator proves a fix did not break functionality.
Tests only rely on the standard library so they run offline.
"""
import os
import sqlite3
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sample_app import auth, db  # noqa: E402


class AuthTests(unittest.TestCase):
    def test_hash_is_deterministic(self):
        h1 = auth.hash_password("s3cret", "salt")
        h2 = auth.hash_password("s3cret", "salt")
        self.assertEqual(h1, h2)

    def test_verify_password_roundtrip(self):
        stored = auth.hash_password("s3cret", "salt")
        self.assertTrue(auth.verify_password("s3cret", "salt", stored))
        self.assertFalse(auth.verify_password("wrong", "salt", stored))


class DbTests(unittest.TestCase):
    def setUp(self):
        self.conn = sqlite3.connect(":memory:")
        self.conn.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT)")
        self.conn.execute("INSERT INTO users (username) VALUES ('alice')")
        self.conn.commit()

    def tearDown(self):
        self.conn.close()

    def test_find_existing_user(self):
        row = db.find_user(self.conn, "alice")
        self.assertIsNotNone(row)
        self.assertEqual(row[1], "alice")

    def test_find_missing_user(self):
        self.assertIsNone(db.find_user(self.conn, "bob"))


if __name__ == "__main__":
    unittest.main()
