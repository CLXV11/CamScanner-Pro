#!/usr/bin/env bash
# Integration test: CAM-SEC Scanner vs local mock camera (localhost only).
# Exits 0 on PASS, 1 on any failure. No internet access required.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCANNER="$ROOT/cam_scanner.sh"
PORT="${TEST_PORT:-18899}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"; kill "$MOCK_PID" 2>/dev/null || true' EXIT

fails=0
check() { # $1=name $2=condition(0/1)
    if [[ "$2" -eq 0 ]]; then printf '[PASS] %s\n' "$1"
    else printf '[FAIL] %s\n' "$1"; fails=$((fails+1)); fi
}

python3 "$ROOT/tests/mock_camera.py" "$PORT" & MOCK_PID=$!
sleep 0.6

# --- negative tests ---
bash "$SCANNER" --target 999.1.1.1 --i-own-targets >/dev/null 2>&1
check "invalid IP rejected (exit 4)" $(( $? == 4 ? 0 : 1 ))

bash "$SCANNER" --target 8.8.8.8 --i-own-targets >/dev/null 2>&1
check "public target refused (exit 4)" $(( $? == 4 ? 0 : 1 ))

# --- positive test: full scan against mock ---
CAMSEC_HOME="$WORK" CAMSEC_TEST_HTTP_PORT="$PORT" CAMSEC_TEST_ONVIF_PORT="$PORT" \
    bash "$SCANNER" --target 127.0.0.1 --quick --i-own-targets \
                    --report both --auth-test >"$WORK/out.txt" 2>"$WORK/err.txt"
rc=$?
check "scan completes rc=0" $(( rc == 0 ? 0 : 1 ))

JF="$(ls -t "$WORK"/reports/*.json 2>/dev/null | head -n1)"
[[ -n "$JF" ]]
check "JSON report produced" $?

python3 -m json.tool "$JF" >/dev/null 2>&1
check "JSON report is valid" $?

python3 - "$JF" <<'PYEOF'
import json, sys
d = json.load(open(sys.argv[1]))
finds = {f["title"]: f for f in d["findings"]}
ok = True
ok &= d["device"]["vendor"] == "Hikvision"
ok &= any("CVE-2017-7921" in t and f["verification"] == "VERIFIED" for t, f in finds.items())
ok &= any("CVE-2017-7925" in t and f["verification"] == "VERIFIED" for t, f in finds.items())
ok &= any("Environment file" in t and f["severity"] == "HIGH" for t, f in finds.items())
ok &= any(f["verification"] == "NOT_APPLICABLE" and "33044" in t for t, f in finds.items())
sys.exit(0 if ok else 1)
PYEOF
check "findings accurate (VERIFIED only with real evidence)" $?

grep -q "hunter2secret" "$WORK"/reports/* "$WORK"/logs/* 2>/dev/null
check "no secret leakage into reports/logs" $(( $? != 0 ? 0 : 1 ))

# --- self-test ---
CAMSEC_HOME="$WORK" bash "$SCANNER" --self-test >/dev/null 2>&1
check "self-test rc=0" $?

echo ""
if [[ "$fails" -eq 0 ]]; then echo "INTEGRATION TESTS: PASS"; exit 0
else echo "INTEGRATION TESTS: FAIL ($fails)"; exit 1; fi
