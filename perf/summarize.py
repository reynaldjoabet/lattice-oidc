#!/usr/bin/env python3
"""Turns oha's JSON results into a Markdown table. Usage: summarize.py <dir> <scenarios> <duration> <connections> <latency>"""
import json, os, platform, subprocess, sys

directory, scenarios, duration, connections, latency, resilience, topology = sys.argv[1:8]

def ms(seconds):
    return f"{seconds * 1000:.1f}" if seconds is not None else "-"

rows = []
for name in scenarios.split():
    path = os.path.join(directory, f"{name}.json")
    if not os.path.exists(path) or os.path.getsize(path) == 0:
        rows.append(f"| {name} | no result | | | | | | |")
        continue
    data = json.load(open(path))
    summary = data["summary"]
    percentiles = data.get("latencyPercentiles", {})
    codes = data.get("statusCodeDistribution", {})
    ok = sum(count for code, count in codes.items() if code.startswith(("2", "3")))
    total = sum(codes.values()) or 1
    errors = sum(data.get("errorDistribution", {}).values())
    rows.append(
        f"| {name} | {summary['requestsPerSec']:,.0f} | {ms(percentiles.get('p50'))} | {ms(percentiles.get('p95'))} "
        f"| {ms(percentiles.get('p99'))} | {ms(summary.get('slowest'))} | {100 * ok / total:.2f}% | {errors} |"
    )

def cpu():
    try:
        return subprocess.check_output(["sysctl", "-n", "machdep.cpu.brand_string"], text=True).strip()
    except Exception:
        return platform.processor() or platform.machine()

print("# Load test results\n")
print(f"- Duration per scenario: {duration}; connections: {connections} (sign-in: one per core)")
print(f"- Topology: {topology}")
print(f"- Scripted Authlete latency: {latency} ms; resilience layer: {resilience}")
print(f"- Machine: {cpu()}, {os.cpu_count()} cores; the load generator runs on the same machine as the server")
print()
print("| Scenario | Requests/s | p50 (ms) | p95 (ms) | p99 (ms) | Slowest (ms) | Success | Errors |")
print("| --- | --: | --: | --: | --: | --: | --: | --: |")
print("\n".join(rows))

for name in scenarios.split():
    path = os.path.join(directory, f"{name}.json")
    if name == "failover" and os.path.exists(path) and os.path.getsize(path):
        errors = json.load(open(path)).get("errorDistribution", {})
        print("\nFailover: one server was killed half way through; requests that failed because of it:\n")
        print("\n".join(f"- {count} x {message}" for message, count in errors.items()) or "- none")

print("\nStatus codes per scenario (a redirect counts as success above, so check these):\n")
for name in scenarios.split():
    path = os.path.join(directory, f"{name}.json")
    if os.path.exists(path) and os.path.getsize(path):
        codes = json.load(open(path)).get("statusCodeDistribution", {})
        print(f"- {name}: " + (", ".join(f"{code}: {count:,}" for code, count in sorted(codes.items())) or "none"))

distribution = os.path.join(directory, "distribution.txt")
if os.path.exists(distribution) and os.path.getsize(distribution):
    print("\nRequests each server handled (health checks and the warm-up included):\n\n```")
    print(open(distribution).read().rstrip())
    print("```")

metrics = os.path.join(directory, "metrics.txt")
if os.path.exists(metrics):
    wanted = ("lattice_authlete_circuit_open", "lattice_read_cache_lookups_total", "lattice_authlete_executor_tasks", "lattice_sessions_active", "jvm_memory_used_bytes{area=\"heap\"", "jvm_gc_pause_seconds_count")
    lines = [l for l in open(metrics) if l.startswith(wanted)]
    if lines:
        print("\nServer state after the run:\n\n```")
        print("".join(lines).rstrip())
        print("```")
