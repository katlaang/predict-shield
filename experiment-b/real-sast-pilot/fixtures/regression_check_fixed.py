"""A real regression check run as its own subprocess: exercises the fixed
get_user() against a real, disposable in-memory sqlite3 database and
asserts legitimate lookups still return the correct row. Exit code 0 is a
pass; any assertion failure or exception is a nonzero exit, matching
regression_check.py's own convention that a check that cannot complete is
never reported as a pass.
"""
import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from fixed_after import get_user, seed  # noqa: E402


def main() -> int:
    conn = sqlite3.connect(":memory:")
    seed(conn)

    alice = get_user(conn, "alice")
    if alice is None or alice[1] != "alice" or alice[2] != "alice@example.test":
        print("FAIL: get_user('alice') did not return the expected row:", alice)
        return 1

    bob = get_user(conn, "bob")
    if bob is None or bob[1] != "bob":
        print("FAIL: get_user('bob') did not return the expected row:", bob)
        return 1

    missing = get_user(conn, "nobody")
    if missing is not None:
        print("FAIL: get_user('nobody') should return no row, got:", missing)
        return 1

    print("PASS: legitimate get_user lookups behave correctly after the fix")
    return 0


if __name__ == "__main__":
    sys.exit(main())
