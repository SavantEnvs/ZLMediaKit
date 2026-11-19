#!/usr/bin/env bash
#
# mayhem/test.sh — run ZLMediaKit's gating unit tests (tests/CMakeLists.txt GATING_TESTS), built by
# mayhem/build.sh with upstream's normal Release flags into release/linux/Release.
#
# Each test must exit 0 AND print the result line upstream's test emits on success (its own
# known-answer checks: AV1 config parsing, HLS cookie metadata, RTP sorting, RTX/TWCC accounting,
# WebRTC SDP negotiation). test_amf reports only through its exit status (its asserted AMF depth
# limit / leading-string cases print nothing on success).
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"
SRC="${SRC:-/mayhem}"
cd "$SRC"

emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

BIN="$SRC/release/linux/Release"
# test name | regex its output must match on success ('' = exit status only)
TESTS=(
  "test_av1_rtmp|^0 failed checks$"
  "test_amf|"
  "test_hls_cookie_data|\[ OK \] HLS player info preserves Session"
  "test_sortor|###### 模拟的rtp seq #####"
  "test_rtx_twcc|^RESULT passed=[1-9][0-9]* failed=0$"
  "test_webrtc_regression|^test_webrtc_regression passed$"
)
passed=0 failed=0
work="$(mktemp -d)"
for entry in "${TESTS[@]}"; do
  name="${entry%%|*}" want="${entry#*|}"
  if [ ! -x "$BIN/$name" ]; then
    echo "FAIL $name: $BIN/$name missing (mayhem/build.sh should have built it)" >&2
    failed=$((failed + 1)); continue
  fi
  # The tests resolve config/www relative to their own directory, as ctest runs them.
  (cd "$BIN" && timeout 120 "./$name") > "$work/$name.log" 2>&1
  rc=$?
  if [ "$rc" -ne 0 ]; then
    echo "FAIL $name: exit $rc"; tail -20 "$work/$name.log"; failed=$((failed + 1))
  elif [ -n "$want" ] && ! grep -Eq "$want" "$work/$name.log"; then
    echo "FAIL $name: expected output /$want/ not found"; tail -20 "$work/$name.log"; failed=$((failed + 1))
  else
    echo "PASS $name"; passed=$((passed + 1))
  fi
done
rm -rf "$work"
emit_ctrf "zlmediakit-gating-tests" "$passed" "$failed" 0
