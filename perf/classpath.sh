#!/usr/bin/env bash
# Prints the classpath of the load-test server (PerfServer), so perf/run.sh can start several JVMs
# directly. sbt 2 writes classpath entries with placeholders; this resolves them.
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT="$(pwd)"
CSR="${COURSIER_CACHE_DIR:-$HOME/Library/Caches/Coursier/v1}"
[ -d "$CSR" ] || CSR="$HOME/.cache/coursier/v1"
# The stylesheets, scripts and fonts: Play serves /assets/* from "public/" on the classpath, and sbt
# only adds it for run and stage, so without this every page of the server is unstyled (404 on /assets).
ASSETS="$ROOT/target/perf-assets"
mkdir -p "$ASSETS"
ln -sfn "$ROOT/public" "$ASSETS/public"
{ printf '%s:' "$ASSETS"; sbt --client "show benchmarks/Runtime/fullClasspath" 2>&1 \
  | sed 's/\x1b\[[0-9;]*[A-Za-z]//g' \
  | grep -o 'Attributed([^)]*)' \
  | sed -e 's/^Attributed(//' -e 's/)$//' -e 's/>sha256-.*$//' \
        -e "s|\${OUT}|$ROOT/target/out|" -e "s|\${CSR_CACHE}|$CSR|" -e "s|\${BASE}|$ROOT|" -e "s|\${SBT_BOOT}|$HOME/.sbt/boot|" \
  | paste -sd: -; } | sed 's/:$//'
