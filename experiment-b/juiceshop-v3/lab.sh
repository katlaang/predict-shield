#!/usr/bin/env bash
# Juice Shop lab orchestration. Usage: lab.sh smoke|develop|test   (run from this directory in CI)
set -euo pipefail
STAGE="$1"
JS_VERSION=19.2.1
W="${RUNNER_TEMP:-/tmp}/js-lab"
mkdir -p "$W"
HERE="$(pwd)"

install_app() {
  if [ ! -d "$W/app" ]; then
    curl -sSL -o "$W/js.tgz" \
      "https://github.com/juice-shop/juice-shop/releases/download/v${JS_VERSION}/juice-shop-${JS_VERSION}_node22_linux_x64.tgz"
    sha256sum "$W/js.tgz" | tee "$W/app-sha256.txt"
    mkdir -p "$W/app" && tar -xzf "$W/js.tgz" -C "$W/app" --strip-components=1
  fi
}

start_app() {   # $1 = session name
  S="$W/$1"; mkdir -p "$S"; rm -f "$S"/trace.txt "$S"/proxy.jsonl
  (cd "$W/app" && NODE_ENV=production PORT=3000 strace -f -ttt -qq -s 256 -e trace=execve,connect,openat \
      -o "$S/trace.txt" node build/app >"$S/app.log" 2>&1 &)
  for i in $(seq 1 120); do curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:3000/ | grep -q 200 && break; sleep 2; done
  curl -s -o /dev/null -w 'app up: %{http_code}\n' http://127.0.0.1:3000/
  python "$HERE/serial_proxy.py" "$S/proxy.jsonl" 3000 benign=9001 attack=9002 >"$S/proxy.log" 2>&1 &
  echo $! > "$S/proxy.pid"
  sleep 2
}

stop_app() {
  pkill -f "node build/app" || true
  sleep 3
  kill "$(cat "$S/proxy.pid")" 2>/dev/null || true
  pkill -f "strace -f -ttt" || true
  sleep 2
}

start_zap() {
  docker rm -f zap >/dev/null 2>&1 || true
  docker pull -q zaproxy/zap-stable
  docker inspect --format '{{index .RepoDigests 0}}' zaproxy/zap-stable | tee "$S/zap-digest.txt"
  docker run -d --name zap --network host zaproxy/zap-stable zap.sh -daemon -host 127.0.0.1 -port 8090 \
    -config api.disablekey=true -config scanner.injectPluginIdInHeader=true -config scanner.threadPerHost=2 >/dev/null
  for i in $(seq 1 90); do curl -s http://127.0.0.1:8090/JSON/core/view/version/ | grep -q version && break; sleep 2; done
  curl -s http://127.0.0.1:8090/JSON/core/view/version/; echo
}

zap_seed_and_scan() {   # $1 = max scan minutes
  # Seed ZAP's site tree by sending one benign pass through ZAP to the attack port (labelled UNKNOWN).
  HTTP_PROXY=http://127.0.0.1:8090 http_proxy=http://127.0.0.1:8090 NO_PROXY= no_proxy= \
    python "$HERE/benign.py" --base http://127.0.0.1:9002 --seed 7 --max-requests 300
  curl -s "http://127.0.0.1:8090/JSON/ascan/action/setOptionMaxScanDurationInMins/?Integer=$1" >/dev/null
  curl -s "http://127.0.0.1:8090/JSON/ascan/action/setOptionThreadPerHost/?Integer=2" >/dev/null
  SID=$(curl -s "http://127.0.0.1:8090/JSON/ascan/action/scan/?url=http://127.0.0.1:9002/&recurse=true" | python -c 'import sys,json;print(json.load(sys.stdin)["scan"])')
  for i in $(seq 1 $(( $1 * 6 + 30 ))); do
    P=$(curl -s "http://127.0.0.1:8090/JSON/ascan/view/status/?scanId=$SID" | python -c 'import sys,json;print(json.load(sys.stdin)["status"])')
    [ "$P" = "100" ] && break; sleep 10
  done
  echo "active scan status: $P"
  curl -s "http://127.0.0.1:8090/JSON/core/view/alerts/?baseurl=http://127.0.0.1:9002" > "$S/alerts.json"
  curl -s "http://127.0.0.1:8090/JSON/ascan/view/scanners/" > "$S/scanners.json"
  docker rm -f zap >/dev/null
}

case "$STAGE" in
  smoke)
    install_app; start_app smoke
    python benign.py --base http://127.0.0.1:9001 --seed 11 --max-requests 300
    start_zap; zap_seed_and_scan 3
    stop_app
    python - "$S" <<'PY'
import json, sys, collections
sys.path.insert(0, "../dvwa-correlation")
import lab, model_js
S = sys.argv[1]
recs, ex, per = model_js.load(__import__("pathlib").Path(S + "/proxy.jsonl"), __import__("pathlib").Path(S + "/trace.txt"))
labels = model_js.label(recs, {})
print("records", len(recs), dict(collections.Counter(l if not l.startswith("zap:") else "zap" for l in labels)))
print("records with no attributed system call:", sum(1 for c in per if not c))
print("benign field names:", sorted({k for e, l in zip(ex, labels) if l == "benign" for k in e.params})[:40])
print("benign paths:", sorted({e.path for e, l in zip(ex, labels) if l == "benign"})[:40])
print("statuses benign:", dict(collections.Counter(r["status"] for r, l in zip(recs, labels) if l == "benign")))
print("alerts:", len(json.load(open(S + "/alerts.json")).get("alerts", [])))
PY
    ;;
  develop)
    install_app; start_app dev
    python benign.py --base http://127.0.0.1:9001 --seed 2026112902 --max-requests 3000
    stop_app
    python model_js.py develop --log "$S/proxy.jsonl" --trace "$S/trace.txt" --docroot "$W/app" --out-dir frozen
    cp "$W/app-sha256.txt" frozen/app-sha256.txt
    ;;
  test)
    install_app; start_app test
    rm -f "$W/stop"
    python benign.py --base http://127.0.0.1:9001 --seed 2026112903 --max-requests 20000 --stop-file "$W/stop" --pause 0.25 \
      > "$S/benign.log" 2>&1 &
    BPID=$!
    start_zap; zap_seed_and_scan 25
    pip install -q 'sqlmap==1.9.11'
    timeout 900 sqlmap -u "http://127.0.0.1:9002/rest/products/search?q=apple" --batch --level 2 --risk 1 --threads 1 \
      --flush-session --output-dir "$W/sqlmap" > "$S/sqlmap.txt" 2>&1 || true
    timeout 900 sqlmap -u "http://127.0.0.1:9002/rest/user/login" --data '{"email":"shopper@example.com","password":"Garden42!"}' \
      --batch --level 2 --risk 1 --threads 1 --flush-session --output-dir "$W/sqlmap" >> "$S/sqlmap.txt" 2>&1 || true
    touch "$W/stop"; wait $BPID || true
    cat "$S/benign.log"
    stop_app
    python model_js.py test --log "$S/proxy.jsonl" --trace "$S/trace.txt" --docroot "$W/app" --alerts "$S/alerts.json" \
      --scanners "$S/scanners.json" --sqlmap-log "$S/sqlmap.txt" --frozen-dir frozen \
      --expected-freeze-sha256 "$FREEZE" --output frozen/test-report.json
    cp "$S/zap-digest.txt" frozen/zap-digest.txt
    python - "$S" <<'PY'
import json, sys
S = sys.argv[1]
a = json.load(open(S + "/alerts.json")).get("alerts", [])
json.dump([{k: x.get(k) for k in ("pluginId", "alert", "risk", "confidence", "url", "param", "method")} for x in a],
          open("frozen/zap-alerts-summary.json", "w"), indent=1)
PY
    ;;
esac
