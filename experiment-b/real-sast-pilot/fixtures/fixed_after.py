"""The fixed version of vulnerable_before.py: the same function, with the
query parameterized instead of string-concatenated. Same enclosing function
name and file role, so the pilot's fingerprint stays comparable across the
fix; same seed data, so the regression check exercises identical behavior.
"""
import sqlite3


def get_user(conn: sqlite3.Connection, username: str):
    cursor = conn.execute("SELECT id, username, email FROM users WHERE username = ?", (username,))
    return cursor.fetchone()


def seed(conn: sqlite3.Connection) -> None:
    conn.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, email TEXT)")
    conn.execute("INSERT INTO users (username, email) VALUES ('alice', 'alice@example.test')")
    conn.execute("INSERT INTO users (username, email) VALUES ('bob', 'bob@example.test')")
    conn.commit()
