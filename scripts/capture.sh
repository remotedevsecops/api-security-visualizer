#!/usr/bin/env bash
# mitmproxy를 crAPI 앞에 리버스 프록시로 세우고, 정상 시나리오를 돌려 HAR로 저장한다.
#   127.0.0.1:8889 (mitmproxy)  →  127.0.0.1:8888 (crAPI)
set -euo pipefail
cd "$(dirname "$0")/.."

MITM=${MITM:-$HOME/.venvs/mitm/bin/mitmdump}
PY=${PY:-$HOME/.venvs/apisec/bin/python}
HAR=data/traffic.har
mkdir -p data
rm -f "$HAR"

"$MITM" --mode reverse:http://127.0.0.1:8888@8889 --listen-host 127.0.0.1 \
        --set hardump="$HAR" -q &
MITM_PID=$!
trap 'kill -INT $MITM_PID 2>/dev/null || true' EXIT

for _ in $(seq 1 30); do
  curl -s -o /dev/null http://127.0.0.1:8889/health && break
  sleep 0.5
done

"$PY" scripts/exercise.py "$@"

kill -INT $MITM_PID
wait $MITM_PID 2>/dev/null || true
trap - EXIT
echo "HAR saved: $HAR ($(du -h "$HAR" | cut -f1))"
