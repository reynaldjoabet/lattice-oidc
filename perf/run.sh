#!/usr/bin/env bash
# HTTP load tests against Lattice with a scripted Authlete (benchmarks/.../PerfServer.java).
#
#   perf/run.sh                       # every scenario, 15 s each
#   DURATION=30s CONNECTIONS=128 perf/run.sh
#   AUTHLETE_LATENCY_MS=25 perf/run.sh       # a slow Authlete: shows threads running out
#   RESILIENCE=off perf/run.sh               # without the Authlete cache/retry/breaker layer, to compare
#   SCENARIOS="health discovery" perf/run.sh
#   LATTICE_STORAGE=postgres DATABASE_URL=... perf/run.sh   # the usual settings apply
#   BASE_URL=http://localhost:9000 START_SERVER=no perf/run.sh   # an already running server
#
# Needs oha (brew install oha), curl and python3. Results go to perf/results/<time>.md.
set -euo pipefail
cd "$(dirname "$0")/.."

DURATION="${DURATION:-15s}"
CONNECTIONS="${CONNECTIONS:-64}"
# Sign-in is bound by Argon2 on the CPU cores, so many connections only queue.
LOGIN_CONNECTIONS="${LOGIN_CONNECTIONS:-$(sysctl -n hw.ncpu 2>/dev/null || nproc)}"
BASE_URL="${BASE_URL:-http://localhost:9000}"
START_SERVER="${START_SERVER:-yes}"
SCENARIOS="${SCENARIOS:-health discovery signin-page authorization-page login metrics}"
RESULTS="perf/results"
STAMP="$(date +%Y%m%d-%H%M%S)"
OUT="$RESULTS/$STAMP.md"
JSON_DIR="$(mktemp -d)"
mkdir -p "$RESULTS"

command -v oha >/dev/null || { echo "oha is needed: brew install oha" >&2; exit 1; }

stop_server() { pkill -f "com.lattice.oidc.perf.PerfServer" 2>/dev/null || true; }

if [ "$START_SERVER" = "yes" ]; then
  stop_server
  echo "Starting the server..."
  PERF_AUTHLETE_LATENCY_MS="${AUTHLETE_LATENCY_MS:-0}" PERF_RESILIENCE="${RESILIENCE:-on}" \
    sbt --client "benchmarks/runMain com.lattice.oidc.perf.PerfServer" > "$JSON_DIR/server.log" 2>&1 &
  trap stop_server EXIT
fi
for _ in $(seq 1 120); do
  curl -s -o /dev/null "$BASE_URL/health/live" && break
  sleep 1
done
curl -s -o /dev/null "$BASE_URL/health/live" || { echo "The server didn't start; see $JSON_DIR/server.log" >&2; exit 1; }

# A session cookie and its CSRF token, reused by every sign-in request.
JAR="$JSON_DIR/cookies"
CSRF="$(curl -s -c "$JAR" -b "$JAR" "$BASE_URL/account" | grep -o 'name="csrfToken" value="[^"]*"' | head -1 | sed 's/.*value="//;s/"//')"
[ -n "$CSRF" ] || { echo "No CSRF token on the sign-in page" >&2; exit 1; }
COOKIE="$(awk 'NR>4 && $6 != "" {printf "%s=%s; ", $6, $7}' "$JAR" | sed 's/; $//')"

# Warm up: JIT, the template engine, connection pools.
oha -z 5s -c 16 --no-tui "$BASE_URL/account" > /dev/null 2>&1 || true

run() { # name  connections  [oha args...]
  local name="$1" connections="$2"; shift 2
  echo "  $name ($connections connections, $DURATION)..."
  oha -z "$DURATION" -c "$connections" -w --no-tui --output-format json -r 0 "$@" > "$JSON_DIR/$name.json" 2>/dev/null || true
}

for scenario in $SCENARIOS; do
  case "$scenario" in
    health)             run health "$CONNECTIONS" "$BASE_URL/health/live" ;;
    discovery)          run discovery "$CONNECTIONS" "$BASE_URL/.well-known/openid-configuration" ;;
    signin-page)        run signin-page "$CONNECTIONS" "$BASE_URL/account" ;;
    authorization-page) run authorization-page "$CONNECTIONS" "$BASE_URL/api/authorization?response_type=code&client_id=42&scope=openid" ;;
    login)              run login "$LOGIN_CONNECTIONS" -m POST -H "Cookie: $COOKIE" -H "Content-Type: application/x-www-form-urlencoded" \
                          -d "csrfToken=$CSRF&loginId=john&password=john&next=account" "$BASE_URL/account/login" ;;
    metrics)            run metrics "$CONNECTIONS" "$BASE_URL/metrics" ;;
    *) echo "Unknown scenario: $scenario" >&2 ;;
  esac
done

# Server-side figures, read before the server is stopped.
curl -s "$BASE_URL/metrics" > "$JSON_DIR/metrics.txt" || true

python3 perf/summarize.py "$JSON_DIR" "$SCENARIOS" "$DURATION" "$CONNECTIONS" "${AUTHLETE_LATENCY_MS:-0}" "${RESILIENCE:-on}" > "$OUT"
cat "$OUT"
echo
echo "Saved to $OUT"
