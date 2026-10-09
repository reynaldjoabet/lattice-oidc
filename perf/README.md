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
perf/run.sh                           # one server, every scenario, 15 s each
DURATION=30s CONNECTIONS=128 perf/run.sh
SCENARIOS="health login" perf/run.sh
INSTANCES=3 perf/run.sh               # three servers behind HAProxy (see "Behind a load balancer")
```

It starts Lattice in production mode with a scripted Authlete (`PerfServer`), signs in once to get a session cookie and CSRF token, runs each scenario with `oha`, stops everything, and writes `perf/results/<time>.md`.

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
| `INSTANCES` | `1` | How many Lattice servers (separate JVMs). More than one puts a proxy in front. |
| `PROXY` | `haproxy` if `INSTANCES` > 1, else `none` | `haproxy`, `nginx` or `none`. Set it with one server to measure the proxy hop. |
| `BALANCE` | `leastconn` | `leastconn` or `roundrobin`. |
| `SHARED_STATE` | `database` | With several servers: `database` starts PostgreSQL and Redis, which they share; `none` keeps each server's state in memory. |
| `CACHE` | `redis` | The read cache with a shared database: `none`, `local` or `redis`. |
| `PERF_JAVA_OPTS` | `-Xms512m -Xmx1g` | JVM options for each server. |
| `START_SERVER`, `BASE_URL` | `yes`, `http://127.0.0.1:9000` | Use `START_SERVER=no` to test a server you started yourself, such as a real deployment. |

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

## Behind a load balancer

A deployment runs several Lattice servers behind a proxy that spreads requests and takes a dead server out. `INSTANCES=N perf/run.sh` builds that on one machine:

```text
oha  ->  HAProxy or nginx (127.0.0.1:9000)  ->  Lattice servers (9101, 9102, ...)  ->  PostgreSQL + Redis
```

- **Real, separate JVMs,** each with its own heap and garbage collector, in production mode.
- **Shared state,** as in a deployment: with `SHARED_STATE=database` the servers use one PostgreSQL (sessions, accounts, audit) and one Redis (pending sign-ins, rate-limit counters, read cache). A sign-in on one server is then valid on the next, which is what a proxy without sticky sessions needs. They share the session-cookie secret too.
- **Health checks.** HAProxy checks `/health/live` every second and removes a server after two failures. nginx (open source) checks passively, taking a server out for a second after two failed requests.
- **Proxy headers.** The proxy adds `X-Forwarded-For`, and the allowed-hosts filter sees the proxy's address, as in production.

```sh
INSTANCES=3 perf/run.sh                                    # HAProxy, least connections
INSTANCES=3 PROXY=nginx BALANCE=roundrobin perf/run.sh
INSTANCES=3 SCENARIOS="signin-page failover" perf/run.sh   # also kills a server half way through
PROXY=haproxy perf/run.sh                                  # one server behind the proxy
```

Needs `haproxy` or `nginx`, and for `SHARED_STATE=database` also `postgres`, `initdb`, `pg_ctl`, `createdb` and `redis-server` (`brew install haproxy postgresql@18 redis`). The report lists how many requests each server handled, which shows whether the balancing was even.

**The `failover` scenario** runs last. Halfway through, it kills one server and counts the requests that failed. It needs `INSTANCES` of 2 or more.

### What it showed (Apple M1, in-memory state per server, 3 servers)

| Test | Result |
| --- | --- |
| Even spread, HAProxy `leastconn`, 10 s of the sign-in page | 33,857 / 30,856 / 36,246 requests per server |
| Even spread, nginx `roundrobin` | 35,693 / 35,690 (one server killed first) |
| HAProxy, one server killed half way through 20 s under load | 22 of about 87,000 requests failed (99.97% succeeded), all "connection closed before message completed", i.e. in flight on the dead server |
| nginx, the same | none failed |
| One server, direct vs through the proxy, health check | 22,125 / 17,021 (HAProxy) / 15,696 (nginx) requests per second |
| One server, direct vs through the proxy, sign-in page | 6,726 / 6,382 (HAProxy) / 6,625 (nginx) |

- **The proxy hop costs a quarter on the lightest request and little on real pages,** because there the server's work dominates.
- **The difference in failover is configuration, not quality.** nginx retries a request that was in flight on a server that died, if it is safe to repeat (a `GET`). HAProxy retries only failed connections unless told to (`retry-on`). For writes, retrying a request that may have been processed is not safe either way.
- **The HAProxy config follows the HAProxy manual and the failover test is unchanged.** `perf/proxy/haproxy.cfg.template` uses `http-reuse safe`, the manual's recommended mode (`aggressive` is for clients that can retry, and writes can't be retried safely), and it drops `on-marked-down shutdown-sessions`, which the manual reserves for stuck backends and which would also cut sign-ins that were about to finish. It retries only connection failures, and sets `hard-stop-after 30s`. `nbthread` is left to HAProxy's CPU detection, which reports 8 usable CPUs here; forcing one thread gave 15.8k and 18.7k requests per second against 20.2k and 18.9k for automatic, within the noise. Failover with three servers still loses about 22 in-flight requests out of tens of thousands, because the proxy can't know whether a request on a dead server was processed.
- **The config doesn't raise throughput on one machine.** Its settings protect a real deployment (slow clients, a server that stops answering, a cold start), which this test doesn't stress. Measuring them needs the load generator on another machine.
- **Throughput with three servers on one machine is lower than with one.** The three JVMs, the proxy and the load generator share 8 cores. Adding servers can't add capacity on one machine; this setup tests the balancing, the health checks and failover, not scaling. To measure scaling, run the servers and the load generator on separate machines (`START_SERVER=no`).

### Caveats

- **The database costs aren't in the `SHARED_STATE=none` numbers.** With in-memory state per server there's no PostgreSQL or Redis latency, so sign-in, sessions and the read cache look faster than they are. Use `SHARED_STATE=database` (the default) for those.
- **A broken PostgreSQL install stops the default mode.** If `initdb` doesn't run (for example, "Library not loaded: libssl.3.dylib" after a Homebrew update removed `openssl@3`), the script says so; `brew reinstall postgresql@18` fixes it. `SHARED_STATE=none` works without it. The database mode has therefore not been run in the numbers above.

### Read cache: none, local (Caffeine) and Redis

Three servers behind HAProxy, a shared PostgreSQL (`lattice_perf` database on the local server) and Redis, the `account` scenario (a signed-in page, 64 connections, 15 s per run). Lattice's cache types are `none`, `local` (in-process Caffeine, the one closest to "Play's cache") and `redis`. Cache hits were checked in the server metrics: over 99% of session and user lookups were hits with both caches.

| Cache | Round 1 | Round 2 | Average | p50 (ms), rounds 1 / 2 |
| --- | --: | --: | --: | --: |
| `none` | 963 | 763 | 863 | 46 / 62 |
| `local` | 971 | 914 | 943 | 49 / 51 |
| `redis` | 812 | 822 | 817 | 60 / 57 |

- **`local` is about 9% faster than none, and `redis` about 5% slower.** The round-to-round spread for `none` is 26%, so only the Redis result is clearly a difference. Redis answers each cached lookup over the network, so it adds a round trip per lookup; with a local PostgreSQL, a query costs about the same, so there's nothing to save.
- **The cache didn't remove most of the database work.** The account page also queries identity links, the authenticator-app check and passkeys on every request, none of which are cached.
- **Pool exhaustion gave HTTP 500 errors in 2 of 8 `local` runs** (24 and 27 of about 2,250 and 8,400 requests). The server log shows `Connection is not available, request timed out ... (total=10, active=10, waiting=5)`: each server's 10-connection pool was full. No `none` or `redis` run (5 in total) produced such errors. That is too few runs to blame the cache, but any change that speeds the server up can push load onto the pool. Before comparing caches on pure speed, raise `DATABASE_POOL_SIZE` and recount the errors; the production overlay sets 10 per replica too.

**Pool size: 10 or 20 connections per server.** Three servers, the local cache, 64 connections, the `account` scenario, 15 s per run, six runs each, alternating. Run on a quieter machine (load average falling from 10 to 6 at the start):

| Pool | Requests/s, six runs | Average | p99 (ms), six runs | HTTP 500s |
| --: | --- | --: | --- | --: |
| 10 | 1,106 · 994 · 978 · 979 · 888 · 791 | 956 | 315 · 304 · 308 · 315 · 385 · 401 (average 338) | 0 in 6 runs |
| 20 | 969 · 1,021 · 1,011 · 873 · 563 · 808 | 874 | 391 · 393 · 404 · 446 · 1,145 · 499 (average 546) | 1 in 6 runs |

Pool 10 gives about 9% more throughput on average and a lower p99. The two pool sizes behave the same way on errors: the 500s occur under load spikes, and an earlier, more loaded session had them at both sizes. A larger pool doesn't remove the errors, it only moves work onto the database sooner, which raises the tail. Keep 10 per replica, and expect 500s under overload until the database work per request is lower (for example, caching identity links and passkeys as well).

### Read cache with in-memory storage (no PostgreSQL)

One server behind HAProxy, in-memory stores, the `account` scenario (64 connections, 15 s per run), three rounds with the order of the settings rotated each time. Cache hits were over 99.99% for `local` and `redis` (for example, 172,640 session hits and 6 misses in one run).

| Cache | Round 1 | Round 2 | Round 3 | Average requests/s | p50 (ms) | p99 (ms) |
| --- | --: | --: | --: | --: | --: | --: |
| `none` | 6,939 | 6,579 | 4,461 | 5,993 | 7.7 – 10.9 | 31 – 78 |
| `local` (Caffeine) | 5,751 | 5,426 | 4,018 | 5,065 | 7.9 – 13.6 | 43 – 54 |
| `redis` | 2,486 | 2,600 | 2,115 | 2,400 | 19.0 – 22.3 | 103 – 161 |

- **No cache is fastest, then `local`, then `redis`, in every round,** whatever the run order. Round 3 is slower for all three, which looks like machine drift, so compare within a round.
- **With a hash map as the store, a cache can only add cost.** A hit stores and reads JSON (about 15% slower for `local`), and `redis` adds two network round trips per request, one for the user and one for the session (about 60% slower).
- **PostgreSQL is the main cost of this page.** The same page ran at about 1,000 requests per second with PostgreSQL and 5,000–7,000 with in-memory stores. The cache pays off only against a store that is slower than the cache.
