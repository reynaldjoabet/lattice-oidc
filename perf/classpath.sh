#!/usr/bin/env bash
# Prints the classpath of the load-test server (PerfServer), so perf/run.sh can start several JVMs
# directly. sbt 2 writes classpath entries with placeholders; this resolves them.
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT="$(pwd)"
CSR="${COURSIER_CACHE_DIR:-$HOME/Library/Caches/Coursier/v1}"
[ -d "$CSR" ] || CSR="$HOME/.cache/coursier/v1"
# The stylesheets, scripts and fonts, with the ".md5" next to each that sbt-digest writes when packaging.
# Play serves /assets/* from "public/" on the classpath, and sbt only adds it for run and stage, so
# without this every page of the server is unstyled (404 on /assets); without the digests, every page
# render searches every JAR for five files that were never there (62% of a sign-in page's CPU).
ASSETS="$ROOT/target/perf-assets"
rm -rf "$ASSETS"
mkdir -p "$ASSETS"
( cd "$ROOT/public" && find . -type f ) | while read -r file; do
  mkdir -p "$ASSETS/public/$(dirname "$file")"
  cp "$ROOT/public/$file" "$ASSETS/public/$file"
  md5 -q "$ROOT/public/$file" 2>/dev/null > "$ASSETS/public/$file.md5" || md5sum "$ROOT/public/$file" | cut -d' ' -f1 > "$ASSETS/public/$file.md5"
done
{ printf '%s:' "$ASSETS"; sbt --client "show benchmarks/Runtime/fullClasspath" 2>&1 \
  | sed 's/\x1b\[[0-9;]*[A-Za-z]//g' \
  | grep -o 'Attributed([^)]*)' \
  | sed -e 's/^Attributed(//' -e 's/)$//' -e 's/>sha256-.*$//' \
        -e "s|\${OUT}|$ROOT/target/out|" -e "s|\${CSR_CACHE}|$CSR|" -e "s|\${BASE}|$ROOT|" -e "s|\${SBT_BOOT}|$HOME/.sbt/boot|" \
  | paste -sd: -; } | sed 's/:$//'
