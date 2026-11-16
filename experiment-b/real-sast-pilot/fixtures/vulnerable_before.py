"""A real, disposable lab target for the SAST fix-verification pilot: a
classic SQL injection via string concatenation. Not production code and
never imported outside this pilot.
"""
import sqlite3


def get_user(conn: sqlite3.Connection, username: str):
    cursor = conn.execute("SELECT id, username, email FROM users WHERE username = '" + username + "'")
    return cursor.fetchone()


def seed(conn: sqlite3.Connection) -> None:
    conn.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, email TEXT)")
    conn.execute("INSERT INTO users (username, email) VALUES ('alice', 'alice@example.test')")
    conn.execute("INSERT INTO users (username, email) VALUES ('bob', 'bob@example.test')")
    conn.commit()
