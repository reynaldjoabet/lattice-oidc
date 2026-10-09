#!/usr/bin/env bash
# HTTP load tests against Lattice with a scripted Authlete (benchmarks/.../PerfServer.java).
#
#   perf/run.sh                                  # one server, every scenario, 15 s each
#   INSTANCES=3 perf/run.sh                      # three servers behind HAProxy, sharing PostgreSQL and Redis
#   INSTANCES=3 PROXY=nginx BALANCE=roundrobin perf/run.sh
#   INSTANCES=3 SHARED_STATE=none perf/run.sh    # in-memory state per server: no database, so no database cost
#   INSTANCES=3 SCENARIOS="signin-page failover" perf/run.sh   # stops a server half way through
#   PROXY=haproxy perf/run.sh                    # one server behind the proxy, to measure the proxy hop
#   DURATION=30s CONNECTIONS=128 perf/run.sh
#   AUTHLETE_LATENCY_MS=25 perf/run.sh           # a slow Authlete: shows threads running out
#   RESILIENCE=off perf/run.sh                   # without the Authlete cache/retry/breaker layer
#   BASE_URL=https://login.example.com START_SERVER=no perf/run.sh   # an already running deployment
#
# Needs oha (brew install oha), curl and python3; for INSTANCES > 1 also haproxy (or nginx),
# postgres and redis-server (brew install haproxy postgresql@18 redis). Results: perf/results/<time>.md.
set -euo pipefail
cd "$(dirname "$0")/.."

DURATION="${DURATION:-15s}"
CONNECTIONS="${CONNECTIONS:-64}"
# Sign-in is bound by Argon2 and memory bandwidth, so many connections only queue.
LOGIN_CONNECTIONS="${LOGIN_CONNECTIONS:-$(sysctl -n hw.ncpu 2>/dev/null || nproc)}"
INSTANCES="${INSTANCES:-1}"
START_SERVER="${START_SERVER:-yes}"
BALANCE="${BALANCE:-leastconn}"          # leastconn | roundrobin
CACHE="${CACHE:-redis}"                   # read cache with several servers: none | local | redis
PUBLIC_PORT="${PUBLIC_PORT:-9000}"
# 127.0.0.1, not localhost: the proxy listens on IPv4, and a load tool may try IPv6 first.
BASE_URL="${BASE_URL:-http://127.0.0.1:$PUBLIC_PORT}"
SCENARIOS="${SCENARIOS:-health discovery signin-page authorization-page login metrics}"
if [ -z "${PROXY:-}" ]; then
  if [ "$INSTANCES" -gt 1 ]; then PROXY=haproxy; else PROXY=none; fi
fi
JAVA_OPTS="${PERF_JAVA_OPTS:--Xms512m -Xmx1g}"
WORK="perf/.work"
RESULTS="perf/results"
STAMP="$(date +%Y%m%d-%H%M%S)"
OUT="$RESULTS/$STAMP.md"
TMP="$(mktemp -d)"
mkdir -p "$RESULTS"

command -v oha >/dev/null || { echo "oha is needed: brew install oha" >&2; exit 1; }
[[ "$DURATION" =~ ^[0-9]+s$ ]] || { echo "DURATION is in seconds, like 15s" >&2; exit 1; }
[ "$INSTANCES" -ge 1 ] || { echo "INSTANCES must be 1 or more" >&2; exit 1; }

PIDS=()          # everything started here, stopped on exit
INSTANCE_PIDS=() # the Lattice servers
INSTANCE_PORTS=()

cleanup() {
  for pid in "${PIDS[@]:-}"; do [ -n "$pid" ] && kill "$pid" 2>/dev/null || true; done
  if [ -d "$WORK/pg" ]; then pg_ctl -D "$WORK/pg" stop -m immediate >/dev/null 2>&1 || true; fi
  rm -rf "$WORK" "$TMP"
}
trap cleanup EXIT

wait_for() { # url  seconds
  for _ in $(seq 1 "$2"); do curl -s -o /dev/null --max-time 2 "$1" && return 0; sleep 1; done
  return 1
}

if [ "$START_SERVER" = "yes" ]; then
  rm -rf "$WORK"; mkdir -p "$WORK"
  echo "Resolving the classpath..."
  CP="$(perf/classpath.sh)"
  [ -n "$CP" ] || { echo "No classpath; does 'sbt --client benchmarks/compile' work?" >&2; exit 1; }

  STATE_ENV=()
  if [ "$INSTANCES" -gt 1 ] && [ "${SHARED_STATE:-database}" = "database" ] && [ "${EXTERNAL_STATE:-no}" != "yes" ]; then
    # Several servers only work if they share their state: sign-ins, sessions and counters.
    for tool in postgres initdb pg_ctl createdb redis-server; do
      command -v "$tool" >/dev/null || { echo "$tool is needed for INSTANCES > 1 (brew install postgresql@18 redis)" >&2; exit 1; }
    done
    initdb --version >/dev/null 2>&1 || {
      echo "PostgreSQL's tools don't run here (often a missing library after a Homebrew update)." >&2
      echo "Fix it (for example: brew reinstall postgresql@18), or run without a database:" >&2
      echo "  SHARED_STATE=none INSTANCES=$INSTANCES perf/run.sh" >&2
      exit 1
    }
    echo "Starting PostgreSQL and Redis..."
    initdb -D "$WORK/pg" -U lattice --auth=trust -E UTF8 >/dev/null
    # Unix sockets off (their path would be too long here); defaults otherwise, so writes are durable.
    pg_ctl -D "$WORK/pg" -o "-p 55432 -c unix_socket_directories= -c listen_addresses=127.0.0.1 -c max_connections=200" \
      -l "$WORK/pg.log" -w start >/dev/null
    createdb -h 127.0.0.1 -p 55432 -U lattice lattice
    redis-server --port 56379 --bind 127.0.0.1 --save "" --appendonly no --dir "$WORK" > "$WORK/redis.log" 2>&1 &
    PIDS+=($!)
    STATE_ENV=(LATTICE_STORAGE=postgres DATABASE_URL=jdbc:postgresql://127.0.0.1:55432/lattice DATABASE_USERNAME=lattice
               LATTICE_SHORT_LIVED_STATE=redis REDIS_URL=redis://127.0.0.1:56379 LATTICE_CACHE="$CACHE")
  fi

  start_instance() { # number  port
    mkdir -p "$WORK/inst-$1"
    (
      cd "$WORK/inst-$1"
      exec env PERF_PORT="$2" PERF_PUBLIC_PORT="$PUBLIC_PORT" PERF_AUTHLETE_LATENCY_MS="${AUTHLETE_LATENCY_MS:-0}" \
        PERF_RESILIENCE="${RESILIENCE:-on}" ${STATE_ENV[@]+"${STATE_ENV[@]}"} \
        java $JAVA_OPTS -cp "$CP" com.lattice.oidc.perf.PerfServer > out.log 2>&1
    ) &
    PIDS+=($!); INSTANCE_PIDS+=($!); INSTANCE_PORTS+=("$2")
  }

  echo "Starting $INSTANCES Lattice server(s)..."
  for n in $(seq 1 "$INSTANCES"); do
    if [ "$PROXY" = "none" ] && [ "$INSTANCES" -eq 1 ]; then port="$PUBLIC_PORT"; else port=$((9100 + n)); fi
    start_instance "$n" "$port"
    # The first one migrates and seeds the database alone; the others start once it's up.
    if [ "$n" -eq 1 ]; then
      wait_for "http://127.0.0.1:$port/health/live" 120 || { echo "Server 1 didn't start; see $WORK/inst-1/out.log" >&2; exit 1; }
    fi
  done
  for port in "${INSTANCE_PORTS[@]}"; do
    wait_for "http://127.0.0.1:$port/health/live" 120 || { echo "A server on $port didn't start" >&2; exit 1; }
  done

  if [ "$PROXY" != "none" ]; then
    command -v "$PROXY" >/dev/null || { echo "$PROXY isn't installed" >&2; exit 1; }
    echo "Starting $PROXY on port $PUBLIC_PORT ($BALANCE)..."
    SERVERS=""
    for n in $(seq 1 "$INSTANCES"); do
      port="${INSTANCE_PORTS[$((n - 1))]}"
      if [ "$PROXY" = "haproxy" ]; then SERVERS="$SERVERS  server s$n 127.0.0.1:$port"$'\n'
      else SERVERS="$SERVERS    server 127.0.0.1:$port max_fails=2 fail_timeout=1s;"$'\n'; fi
    done
    if [ "$PROXY" = "haproxy" ]; then
      TEMPLATE="${HAPROXY_TEMPLATE:-perf/proxy/haproxy.cfg.template}"; CONFIG="$WORK/haproxy.cfg"; BAL="$BALANCE"
    else
      TEMPLATE=perf/proxy/nginx.conf.template; CONFIG="$WORK/nginx.conf"
      if [ "$BALANCE" = "leastconn" ]; then BAL="least_conn;"; else BAL="# round robin (the default)"; fi
      mkdir -p "$WORK"
    fi
    PROXY_THREADS="${PROXY_THREADS:-}" python3 - "$TEMPLATE" "$CONFIG" "$PUBLIC_PORT" "$BAL" "$SERVERS" "$(pwd)/$WORK" <<'PY'
import os, sys
template, config, port, balance, servers, work = sys.argv[1:7]
text = open(template).read()
for key, value in {"__PUBLIC_PORT__": port, "__BALANCE__": balance, "__SERVERS__": servers.rstrip("\n"), "__WORK__": work, "__NBTHREAD_LINE__": (f"nbthread {os.environ['PROXY_THREADS']}" if os.environ.get("PROXY_THREADS") else "# nbthread: auto")}.items():
    text = text.replace(key, value)
open(config, "w").write(text)
PY
    if [ "$PROXY" = "haproxy" ]; then
      haproxy -f "$CONFIG" > "$WORK/proxy.log" 2>&1 &
    else
      nginx -c "$(pwd)/$CONFIG" -p "$(pwd)/$WORK/" -g 'daemon off;' > "$WORK/proxy.log" 2>&1 &
    fi
    PIDS+=($!)
  fi
fi
wait_for "$BASE_URL/health/live" 60 || { echo "Nothing answers at $BASE_URL" >&2; exit 1; }

# A session cookie and its CSRF token, reused by every sign-in request. They're signed with a secret
# every server shares, so any server accepts them.
JAR="$TMP/cookies"
CSRF="$(curl -s -c "$JAR" -b "$JAR" "$BASE_URL/account" | grep -o 'name="csrfToken" value="[^"]*"' | head -1 | sed 's/.*value="//;s/"//')"
[ -n "$CSRF" ] || { echo "No CSRF token on the sign-in page" >&2; exit 1; }
COOKIE="$(awk 'NR>4 && $6 != "" {printf "%s=%s; ", $6, $7}' "$JAR" | sed 's/; $//')"

# Warm up: JIT, the template engine, connection pools, and every server behind the proxy.
oha -z 8s -c 32 --no-tui "$BASE_URL/account" > /dev/null 2>&1 || true

run() { # name  connections  [oha args...]
  local name="$1" connections="$2"; shift 2
  echo "  $name ($connections connections, $DURATION)..."
  oha -z "$DURATION" -c "$connections" -w --no-tui --output-format json -r 0 "$@" > "$TMP/$name.json" 2>/dev/null || true
}

# The failover scenario stops a server, so it runs last.
ORDERED=""; FAILOVER=""
for scenario in $SCENARIOS; do
  if [ "$scenario" = "failover" ]; then FAILOVER="failover"; else ORDERED="$ORDERED $scenario"; fi
done
for scenario in $ORDERED $FAILOVER; do
  case "$scenario" in
    health)             run health "$CONNECTIONS" "$BASE_URL/health/live" ;;
    discovery)          run discovery "$CONNECTIONS" "$BASE_URL/.well-known/openid-configuration" ;;
    signin-page)        run signin-page "$CONNECTIONS" "$BASE_URL/account" ;;
    authorization-page) run authorization-page "$CONNECTIONS" "$BASE_URL/api/authorization?response_type=code&client_id=42&scope=openid" ;;
    login)              run login "$LOGIN_CONNECTIONS" -m POST -H "Cookie: $COOKIE" -H "Content-Type: application/x-www-form-urlencoded" \
                          -d "csrfToken=$CSRF&loginId=john&password=john&next=account" "$BASE_URL/account/login" ;;
    metrics)            run metrics "$CONNECTIONS" "$BASE_URL/metrics" ;;
    failover)
      if [ "$INSTANCES" -lt 2 ] || [ "$START_SERVER" != "yes" ]; then
        echo "  failover needs INSTANCES of 2 or more (started here); skipped"
        continue
      fi
      echo "  failover (a server is killed half way through $DURATION)..."
      run failover "$CONNECTIONS" "$BASE_URL/account" &
      load=$!
      sleep $(( ${DURATION%s} / 2 ))
      kill -9 "${INSTANCE_PIDS[0]}" 2>/dev/null || true
      wait "${INSTANCE_PIDS[0]}" 2>/dev/null || true   # keeps bash from printing "Killed"
      echo "    stopped the server on port ${INSTANCE_PORTS[0]}"
      wait "$load" || true
      ;;
    *) echo "Unknown scenario: $scenario" >&2 ;;
  esac
done

# How the proxy spread the requests: each server's own count (health checks included).
: > "$TMP/distribution.txt"
if [ "$START_SERVER" = "yes" ]; then
  for i in "${!INSTANCE_PORTS[@]}"; do
    port="${INSTANCE_PORTS[$i]}"
    total="$(curl -s --max-time 3 "http://127.0.0.1:$port/metrics" | awk '/^http_server_requests_seconds_count/ {s += $NF} END {printf "%d", s}')" || total=""
    echo "server $((i + 1)) (port $port): ${total:-stopped}" >> "$TMP/distribution.txt"
  done
  curl -s "http://127.0.0.1:${INSTANCE_PORTS[$(( ${#INSTANCE_PORTS[@]} - 1 ))]}/metrics" > "$TMP/metrics.txt" || true
else
  curl -s "$BASE_URL/metrics" > "$TMP/metrics.txt" || true
fi

if [ "$PROXY" = "none" ]; then TOPOLOGY="$INSTANCES server, no proxy"; else TOPOLOGY="$INSTANCES server(s) behind $PROXY ($BALANCE)"; fi
if [ "$INSTANCES" -gt 1 ] && [ "$START_SERVER" = "yes" ]; then
  if [ "${SHARED_STATE:-database}" = "none" ]; then TOPOLOGY="$TOPOLOGY, in-memory state per server (no database)"; else TOPOLOGY="$TOPOLOGY, shared PostgreSQL and Redis (cache: $CACHE)"; fi
fi
[ "$START_SERVER" = "yes" ] || TOPOLOGY="an existing deployment at $BASE_URL"
python3 perf/summarize.py "$TMP" "$ORDERED $FAILOVER" "$DURATION" "$CONNECTIONS" "${AUTHLETE_LATENCY_MS:-0}" "${RESILIENCE:-on}" "$TOPOLOGY" > "$OUT"
cat "$OUT"
echo
echo "Saved to $OUT"
