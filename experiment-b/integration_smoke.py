"""Run against the localhost-only Docker Compose lab, not production endpoints."""
import json
import os
import time
import urllib.error
import urllib.request
from run import run

def await_lab():
    for attempt in range(60):
        try:
            with urllib.request.urlopen("http://127.0.0.1:18081/healthz", timeout=2) as a:
                with urllib.request.urlopen("http://127.0.0.1:18082/healthz", timeout=2) as b:
                    if a.status == 200 and b.status == 200:
                        return
        except (OSError, TimeoutError):
            pass
        time.sleep(2)
    raise RuntimeError("Lab services did not become healthy within readiness window")

def main():
    await_lab()
    token = os.environ.get("LAB_TOKEN")
    if not token:
        raise RuntimeError("LAB_TOKEN must be set")
    before = run(allow_correction=False)
    assert before["final_outcome"] == "NOT VERIFIED", before
    after = run(allow_correction=True, token=token)
    assert after["started_outcome"] == "NOT VERIFIED", after
    assert after["final_outcome"] == "VERIFIED", after
    assert len(after["actions"]) == 1 and after["actions"][0]["acknowledged"], after
    os.makedirs("reports", exist_ok=True)
    with open("reports/experiment-b-smoke.json", "w", encoding="utf-8") as out:
        json.dump({"before": before, "after": after}, out, indent=2)
    print("PASS: detected inconsistent access, gated correction, and independently rechecked")

if __name__ == "__main__":
    main()
