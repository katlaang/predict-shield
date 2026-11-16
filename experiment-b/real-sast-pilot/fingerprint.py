"""A stable, content-based finding fingerprint for scanners that do not
expose their own (Semgrep's OSS CLI gates its native `fingerprint` field
behind a logged-in Semgrep Cloud Platform session; this pilot runs fully
offline, so it computes one locally instead).

A raw line number is not stable: a patch shifts every line below it. This
instead hashes the rule ID, the file path and the name of the enclosing
function, which stays the same across a one-line fix to that function's
body. It is not as strong as a real scanner's AST-based fingerprint (a
function rename would change it, where a true structural fingerprint might
not), and that limitation is intentional to state rather than hide: see
sast_findings.py's module docstring for what a fingerprint is required to
do, and README/ROADMAP for this limitation recorded against the pilot.
"""
from __future__ import annotations

import ast
import hashlib
from pathlib import Path


def enclosing_function(file_path: str, line: int) -> str:
    """The name of the function enclosing `line` in `file_path`, or
    "<module>" if the line is not inside any function. Raises if the file
    does not parse: a finding in a file this cannot parse is not fingerprinted
    at all, rather than silently assigned a wrong or empty name.
    """
    tree = ast.parse(Path(file_path).read_text())
    best = "<module>"
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            start = node.lineno
            end = getattr(node, "end_lineno", None) or start
            if start <= line <= end:
                best = node.name
    return best


def compute(rule_id: str, file_path: str, line: int) -> str:
    """The pilot's stable finding identity: rule, file, and enclosing
    function, not the line number. Two scans of the same function produce
    the same fingerprint even if the vulnerable line's exact text changes,
    as a fix is expected to change it.
    """
    function_name = enclosing_function(file_path, line)
    key = rule_id + "|" + str(Path(file_path).name) + "|" + function_name
    return hashlib.sha256(key.encode()).hexdigest()[:16]
