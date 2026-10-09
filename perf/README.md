# Performance tests

Two kinds, because they answer different questions.

| | Answers | Tool | Run |
| --- | --- | --- | --- |
| **Micro-benchmarks** | How much CPU does this one piece of code cost? | JMH | `sbt --client "benchmarks/Jmh/run"` |
| **HTTP load tests** | How many requests per second, and how long do they take, for the whole server? | `oha` | `perf/run.sh` |

Neither runs as part of `test`, `stage` or the Docker image. The code is in the `benchmarks/` project.

## Micro-benchmarks

```sh
sbt --client "benchmarks/Jmh/run"                                  # all of them (about 6 minutes)
sbt --client "benchmarks/Jmh/run PasswordHashingBenchmark -t 4"    # one, on four threads
sbt --client "benchmarks/Jmh/run -rf json -rff results.json"       # results as JSON, to compare runs
```

| Benchmark | What it measures |
| --- | --- |
| `PasswordHashingBenchmark` | One Argon2 password check, right and wrong, and creating a hash. The main CPU cost of a sign-in. |
| `TotpBenchmark` | Checking an authenticator code, right and wrong. |
| `SecretCipherBenchmark` | Encrypting and decrypting an authenticator secret (AES-256-GCM), and hashing a recovery code. |
| `ReadCacheBenchmark` | The user lookup made on every signed-in request: directly, through the in-memory read cache, and saving with invalidation. |
| `AuthleteResilienceBenchmark` | What the Authlete resilience layer adds to a call, and what a cache hit saves. |

Each class sets its own warm-up and measurement. Read the `Score` as the time per operation; `Error` is the 99.9% confidence interval, and a large one means the machine was busy.

**How to read them**
- **Compare, don't quote.** The absolute numbers belong to the machine that produced them. What matters is the ratio between two benchmarks in a run, or between two runs of the same one before and after a change.
- **`ReadCacheBenchmark` uses a hash map as the store,** so it's the floor: a cached lookup costs a JSON deserialisation, and is slower than the map. The cache pays off against a real store, such as PostgreSQL, where a lookup is a network round trip. Measure that with `perf/run.sh` against PostgreSQL.
- **Authlete itself is not in the benchmarks.** The scripted Authlete answers instantly, so the resilience numbers are only the layer's own overhead. A real Authlete call is an HTTP request of milliseconds.

## HTTP load tests

```sh
brew install oha                      # once
perf/run.sh                           # every scenario, 15 s each
DURATION=30s CONNECTIONS=128 perf/run.sh
SCENARIOS="health login" perf/run.sh
```

It starts Lattice in production mode with a scripted Authlete (`PerfServer`), signs in once to get a session cookie and CSRF token, runs each scenario with `oha`, stops the server, and writes `perf/results/<time>.md`.

| Scenario | Request | What it exercises |
| --- | --- | --- |
| `health` | `GET /health/live` | The framework alone: filters, routing, a tiny response. The ceiling for everything else. |
| `discovery` | `GET /.well-known/openid-configuration` | An Authlete call, answered from the resilience layer's cache. |
| `signin-page` | `GET /account` | Rendering a page, with CSRF and session handling. |
| `authorization-page` | `GET /api/authorization?...` | An Authlete call that can't be cached, then a stored pending request and a page. |
| `login` | `POST /account/login` | An Argon2 check, a session, and a redirect. Bound by the CPU cores, so it runs one connection per core. |
| `metrics` | `GET /metrics` | The cost of a Prometheus scrape. |

**Settings**

| Variable | Default | Meaning |
| --- | --- | --- |
| `DURATION` | `15s` | How long each scenario runs. |
| `CONNECTIONS` | `64` | Concurrent connections (sign-in uses one per core). |
| `AUTHLETE_LATENCY_MS` | `0` | A delay on every scripted Authlete call. A real one takes a few to tens of milliseconds, so try `25`. |
| `RESILIENCE` | `on` | `off` removes the resilience layer, to see what it does. |
| `SCENARIOS` | all | A space-separated list. |
| `START_SERVER`, `BASE_URL` | `yes`, `http://localhost:9000` | Use `START_SERVER=no` to test a server you started yourself, such as a real deployment. |

PostgreSQL, Redis and the read cache take the usual settings, for example `LATTICE_STORAGE=postgres DATABASE_URL=... LATTICE_SHORT_LIVED_STATE=redis LATTICE_CACHE=redis perf/run.sh`.

**What the numbers mean, and don't**
- **The load generator runs on the same machine as the server,** so they share the CPU. Treat the figures as a baseline for comparing changes, not a capacity promise. For capacity, run `oha` from another machine with `START_SERVER=no`.
- **Latency is measured by the client** and includes queueing when there are more connections than the server has threads. With 64 connections and 32 Authlete threads, a page that waits on Authlete shows about twice the Authlete delay.
- **Read the p99, not just the average.** One slow request in a hundred is what a user notices.

### What a slow Authlete does

Every call to Authlete holds one of 32 threads (`authlete-dispatcher`) while it waits, so the throughput of an Authlete-bound page is at most 32 ÷ the delay. With `AUTHLETE_LATENCY_MS=100` that's 320 requests per second, however fast the rest is. The resilience layer's cache lifts that ceiling for what it can cache:

| 100 ms Authlete, 64 connections | Requests/s |
| --- | --: |
| `authorization-page` (not cacheable), with or without the layer | about 305 |
| `discovery`, without the layer | about 309 |
| `discovery`, with the layer (answered from its cache) | about 16,500 |

To raise the ceiling for pages that can't be cached, raise `AUTHLETE_DISPATCHER_THREADS`. Watch `lattice_authlete_executor_tasks{state="queued"}`: a queue that keeps growing means the pool is saturated.

### Sign-in capacity

Sign-in is the expensive endpoint. One Argon2 check takes about 24 ms on one thread (Apple M1), but it doesn't scale with the cores, because Argon2 is deliberately memory-hungry. Checks per second, from `PasswordHashingBenchmark.verifyCorrectPassword -t N`:

| Threads | Time per check | Checks/s |
| --: | --: | --: |
| 1 | 25 ms | about 40 |
| 4 | 39 ms | about 100 |
| 8 | 69 ms | about 115 |

So about 100 sign-ins per second per server is the ceiling on this machine, and the HTTP `login` scenario (which also renders pages and creates sessions, and shares the CPU with the load generator) reached about 75. Size servers for the sign-in rate you expect at peak, not for the page rate, and expect the `login` p99 to climb long before the other pages do. Run it on your own hardware: the shape holds, but the numbers don't transfer.
