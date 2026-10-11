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
| `token` | `POST /api/token` | Form parsing, the Authlete call and the response, for the endpoint every client uses. |
| `introspection` | `POST /api/introspection` | Resource-server Basic authentication and an Authlete call. |
| `userinfo` | `GET /api/userinfo` | Two Authlete calls and the user's claims. |
| `par` | `POST /api/par` | A pushed authorization request. |
| `revocation` | `POST /api/revocation` | A token revocation. |

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
| `STORAGE` | in memory | `postgres` runs one server on its own throwaway PostgreSQL and Redis (several servers always do). |
| `CACHE` | `redis` | The read cache with a shared database: `none`, `local` or `redis`. |
| `PERF_JAVA_OPTS` | `-Xms2g -Xmx2g` | JVM options for each server. Sign-in is sensitive to the heap size, see "Sign-in capacity". |
| `START_SERVER`, `BASE_URL` | `yes`, `http://127.0.0.1:9000` | Use `START_SERVER=no` to test a server you started yourself, such as a real deployment. |

PostgreSQL, Redis and the read cache take the usual settings, for example `LATTICE_STORAGE=postgres DATABASE_URL=... LATTICE_SHORT_LIVED_STATE=redis LATTICE_CACHE=redis perf/run.sh`.

**What the numbers mean, and don't**
- **The load generator runs on the same machine as the server,** so they share the CPU. Treat the figures as a baseline for comparing changes, not a capacity promise. For capacity, run `oha` from another machine with `START_SERVER=no`.
- **Latency is measured by the client** and includes any queueing when there are more connections than the server can serve at once.
- **Read the p99, not just the average.** One slow request in a hundred is what a user notices.

### What a slow Authlete does

Every call to Authlete blocks while it waits for the network. They used to run on a fixed pool of 32 threads (`authlete-dispatcher`), so the throughput of any page or endpoint that calls Authlete was at most 32 ÷ the delay, however fast the rest was: about 1,300 requests per second at a realistic 25 ms. Now each call runs on its own **virtual thread**, so waiting costs almost nothing, and what limits concurrency is `authlete.max-concurrent-calls` (default 1,000; `AUTHLETE_MAX_CONCURRENT_CALLS`), which protects Authlete and the connection pool. `AUTHLETE_DISPATCHER_EXECUTOR=thread-pool-executor` goes back to the fixed pool (`AUTHLETE_DISPATCHER_THREADS`), which is also what happens on a JVM before Java 21.

| 25 ms Authlete, 128 connections | Fixed pool of 32 | Virtual threads |
| --- | --: | --: |
| `token` | 1,553 (p50 112 ms) | **4,245** (p50 33 ms) |
| `introspection` | 1,234 | **3,961** |
| `authorization-page` | 1,244 | **4,066** |
| `userinfo` (two Authlete calls per request) | 839 | **2,263** |

The p50 is now about the Authlete delay plus 8 ms, and the throughput is limited by the 128 test connections (128 ÷ 25 ms ≈ 5,100) and no longer by the server. With no Authlete delay these endpoints run at 20,000 to 35,000 requests per second (`token` 20,700, `introspection` 26,900, `userinfo` 34,500, `par` 20,400, `revocation` 25,800), so the cost of Lattice's own work around the call is small.

The resilience layer's cache still removes the call altogether for what it can cache (`discovery` with a 100 ms Authlete: about 16,500 requests per second with the cache, about 309 without it, on the old pool).

Watch `lattice_authlete_executor_tasks{state="queued"}` against `lattice_authlete_executor_limit`: a queue that keeps growing while `active` sits at the limit means the limit is too low for the load, or Authlete is slow.

### Sign-in capacity

Sign-in is the expensive endpoint, and it is expensive on purpose: a password check runs Argon2id with 19 MiB of memory and two passes (it was 15 MiB until the cost was raised to OWASP's minimum), so that someone with a stolen database pays that cost for every guess. It doesn't scale with the cores, because it is memory-bound. Two things set how many sign-ins a server can do per second: how fast the Argon2 implementation is, and how much the collector has to do, because every check allocates 15 MiB.

**Why it was about 85 a second, and what changed** (one server, in-memory storage, 8 connections, 12 s; the first four rows are at the old 15 MiB):

| | Sign-ins/s | GC pause, of about 18 s |
| --- | --: | --: |
| password4j's Argon2, 1 GB heap (the old default) | 87 | 2.7 s |
| password4j's Argon2, 2 GB heap | 110 | 1.1 s |
| password4j's Argon2, 4 GB heap, 32 MB G1 regions | 118 | 0.7 s |
| Bouncy Castle's Argon2, 2 GB heap | 162–166 | 0.4 s |
| **Bouncy Castle's Argon2, 19 MiB (today), 2 GB heap** | **109–118** | 0.4–0.6 s |

How it was found: JFR showed 89% of the CPU inside password4j's Argon2 loop (the hashing itself is the cost), and 98% of the allocation as `long[]`, Argon2's memory, which drove 331 young collections that paused the server about 15% of the time. A bigger heap fixes the pauses. For the hashing, the same parameters in Bouncy Castle (already a dependency) took 17.0 ms on one thread against 23.3 ms, and 202 against 124 hashes per second on eight threads. `PasswordHasher` now uses it. Hashes keep the standard format and verify both ways: hashes written by password4j verify here, and hashes written here verify in password4j, so going back stays possible (the tests check both directions, and a literal hash from the old implementation).

The 19 MiB row is the same cost the old library had at 15 MiB (110), at the strength OWASP lists as the minimum, with some of the saving spent on that. In isolation, Bouncy Castle took 22.8 ms per hash on one thread at 19 MiB (17.0 ms at 15 MiB, where password4j took 23.3 ms), and did 144 hashes a second on eight threads (about 190 at 15 MiB).

**So thousands of sign-ins per second per server isn't possible without weakening the hash.** At about 23 ms per hash, 1,000 sign-ins a second need about 23 cores of pure hashing. The options are more cores or more servers (each server's sign-in limit is `lattice.login.hashing-concurrency`, default the number of cores), and keeping password sign-in off the hot path: sessions, passkeys (a signature check, about a tenth of a millisecond) and tokens don't pay for Argon2. Cutting the memory or passes would raise the number and lower the protection by the same factor.

**Heap size matters for sign-in.** Each concurrent check holds 19 MiB, and the churn is more than a gigabyte a second at full speed. Give the JVM headroom: in a container, `MaxRAMPercentage=75` (the image's default) means a 3 GB limit gives about 2.25 GB of heap. The perf harness now defaults to `-Xms2g -Xmx2g`.

## What limited the throughput, and what fixed it

One server, in-memory storage, no read cache, 128 connections, 15 s per scenario. Profiling with JFR (`jcmd <pid> JFR.start settings=profile`) showed three separate limits, none of them in the endpoints' own logic.

| Requests/s | Before | After | Cause removed |
| --- | --: | --: | --- |
| health | 26,457 | **52,204** | Per-request stream in every filter |
| discovery | 17,898 | **33,326** | Per-request stream in every filter |
| signin-page | 6,802 | **25,009** | Missing asset digests, then the filters |
| account (signed in) | 7,135 | **22,613** | Missing asset digests, then the filters |
| authorization-page | 3,259 (p99 1,372 ms) | **21,999** (p99 18 ms) | Full-store eviction scan |
| login (Argon2) | 81 | 73 | Unchanged: bound by memory bandwidth, see "Sign-in capacity" |
| metrics | 5,065 | 6,431 | |

1. **Plain `Filter`s materialize a stream per request.** Play's `Filter` wraps the next action with `Accumulator.flatten`, so every request, in every filter, created a stream and an actor under one shared supervisor. With six filters that supervisor was the ceiling (about 30,000 requests a second at best), and the worker threads sat idle most of the time (about 30% of a core each, 2.3 cores in use of 8). All six are now `EssentialFilter`s (see `FilterSupport`), which transform the response without a stream of their own, as Play's own filters do. This helped every endpoint.
2. **No digest files for the assets.** Play's `Assets.versioned` caches a digest only if `<asset>.md5` exists. There were none, so each of the five asset links in every page re-searched all 266 JARs: 62% of the CPU time of a sign-in page. `build.sbt` now writes an `.md5` per public file. A side effect worth having in production: asset URLs are fingerprinted (`/assets/stylesheets/<md5>-oidc.css`) and sent with `Cache-Control: public, max-age=31536000, immutable`.
3. **Eviction scanned the whole store on every put.** Past 50,000 pending requests, each `put` found the oldest entry by scanning all of them, under a lock shared by the whole JVM. It also meant flooding `/api/authorization` slowed every later request. It now evicts a tenth of the cap in one pass, without that lock.

**Checks that ruled things out**
- **The load generator and the machine are not the limit.** `oha` against a static HAProxy answer reached about 180,000 requests a second with no errors.
- **JVM settings don't matter for the pages.** G1 with `-Xms512m -Xmx1g` was as good as 2 GB heaps, ParallelGC or ZGC; the run-to-run spread (for example 12,600 and 25,200 for the same settings) was larger than any difference. Sign-in is the exception, see "Sign-in capacity".
- **What is left is the framework.** Lattice's own code is under 5% of a sign-in page's CPU samples. The rest is Play's rendering, session cookie and Pekko HTTP.

**Client-side connection errors.** `oha` reports a few thousand "connection reset" errors once there are 128 or more connections, while every response the server did send was a 200 (or a 303). They don't grow with the length of the run, which fits a burst of connections at the start overflowing the accept queue (100 in Pekko by default, 128 on macOS); that is not proven.

### How the causes were found

The method was a loop: measure, check what is saturated, profile, form a hypothesis, test it, fix one thing, measure again. In order, including the guesses that were wrong:

1. **Set the baseline and note what looked odd.** `health` at about 26,000 requests a second, `authorization-page` with a p99 of 1.4 s, and thousands of client "errors" although every response was a 200. One setup throughout (in-memory, no cache), so only one thing changed at a time.
2. **Check whether the CPU was the limit.** `top` during a run showed the server using about 2.3 of 8 cores. A CPU-bound server would use them all, so something else was holding requests back.
3. **Rule out the obvious suspects.**
   - *Logging:* the access log skips `/health/`, and the log file was tiny.
   - *A single socket thread (a wrong guess):* the JFR profile showed Pekko's one network thread nearly idle.
   - *Garbage collection:* it paused about 6.5% of the time, too little to explain a 2x gap.
4. **Check whether the load generator was the limit.** `oha` against a static HAProxy answer reached about 180,000 requests a second with no errors. So the machine and the tool were fine, and the server was the limit.
5. **Look for a serial bottleneck.** Varying the connection count: from 64 connections up, throughput stayed flat at about 30,000 while latency grew in proportion to the connections (Little's law). That pattern means one stage handles requests one at a time while the cores idle. The profile agreed: each worker thread was only about 30% busy.
6. **Find that stage in the profile.** 17% of the samples were in stream and actor creation (`PhasedFusingActorMaterializer.materialize`, `ChildrenContainer`). The callers led to `Accumulator.futureToSink`, which is how Play's plain `Filter` wraps the next action: a stream and an actor per request and per filter, all under one parent. Converting the six filters to `EssentialFilter` took `health` from about 30,000 to 52,000–64,000. The next subsection shows the code before and after.
7. **Ask why the pages did not improve.** `signin-page` stayed near 7,000. Its profile: 62% of the samples were the classloader scanning JARs, called from `DefaultAssetsMetadata.digest`. The layout calls `Assets.versioned` five times per page, and Play caches a digest only when `<asset>.md5` exists. After writing the files in the build, the checks were that pages reference fingerprinted URLs, that the digest equals the file's real md5, and that the staged production app serves them (the first look at the staged build was at a stale folder). The page went from about 7,000 to 21,000.
8. **Explain the 1.4 s tail.** A rare, long stall suggests periodic work. In the in-memory store, once a namespace passed 50,000 entries every `put` scanned all of them, under a lock shared by the whole JVM. To confirm it, the old algorithm was timed in isolation: 16.6 s for 40,000 puts. After the fix, with a test that fails on the old behaviour, `authorization-page` went from 3,300 to 22,000 and its p99 from 1.4 s to 18 ms.
9. **Check what was left.** JVM heap and collector settings: the run-to-run swings were larger than any difference, so nothing changed. On the sign-in page, Lattice's own code is under 5% of the CPU samples. The connection resets stay unexplained.

After every change the same measurement was repeated and the full test suite run. This machine was heavily loaded by other programs, so single numbers swing a lot: the conclusions rest on the profiles and on the before-and-after pattern repeating.

**To repeat it**
- Profile a running server: `jcmd <pid> JFR.start name=p settings=profile duration=20s filename=out.jfr`, run the load, then `jfr print --events jdk.ExecutionSample out.jfr` and count the top frames and their callers. `jdk.ThreadCPULoad` shows which threads are busy.
- Check the load generator: point `oha` at a static HAProxy response (`http-request return status 200 ...`).
- Sweep connections: run `oha -c 32`, `64`, `128`, `256` against one URL and watch whether throughput or latency moves.

### The filter change, step by step

Step 6 above in plain terms. Pekko streams are still used by the server: reading the request body and writing the response go through one stream per request, as before. What changed is that the six filters no longer each start **another** stream.

**What Play does with a request.** The headers arrive and Play finds the action. The action can't produce a response until the body has been read, so Play represents it as an `Accumulator`: a consumer of the body that is waiting to be run, and that will yield the `Result`. Play runs it once, as one stream.

**Before: a plain `Filter`.** The filter was handed a function that returns the finished response:

```java
public final class RequestIdFilter extends Filter {          // play.mvc.Filter

  @Override
  public CompletionStage<Result> apply(
      Function<Http.RequestHeader, CompletionStage<Result>> next, Http.RequestHeader request) {
    String id = ...;
    return next.apply(request.addAttr(REQUEST_ID, id))       // a ready-to-come Result...
        .thenApply(r -> r.withHeader(HEADER, id));
  }
}
```

The body hasn't been read yet, so to hand a filter something that returns a `Result`, Play has to build and start a stream at that moment, so that `next` can really run. Each filter in the chain did this, so one request started about six extra streams. Each stream sets up actors under a shared parent, and in the profile that bookkeeping (`PhasedFusingActorMaterializer.materialize`, `ChildrenContainer`) was 17% of the CPU samples, with the workers idle most of the time.

**After: an `EssentialFilter`.** The filter is handed the action itself and attaches its change to the result, without running anything:

```java
public final class RequestIdFilter extends EssentialFilter { // play.mvc.EssentialFilter

  @Override
  public EssentialAction apply(EssentialAction next) {
    return EssentialAction.of(
        request -> {
          String id = ...;
          Accumulator<ByteString, Result> action = next.apply(request.addAttr(REQUEST_ID, id)); // not running yet
          return action.map(r -> r.withHeader(HEADER, id), FilterSupport.DIRECT);               // "and then do this"
        });
  }
}
```

`next.apply(request)` returns the Accumulator, and `.map(...)` only attaches a function to its result. Play runs the combined action once, in the same single stream it would have run anyway. The filters in the chain just add their small steps to it.

**An answer that is already known.** `HstsFilter` and `RequiredActionsFilter` sometimes answer immediately, with a redirect. They return `Accumulator.done(result)`: a finished value, so no stream at all.

```java
return Accumulator.<ByteString, Result>done(Results.movedPermanently("https://" + request.host() + request.uri()));
```

**`FilterSupport.DIRECT`** is an executor that runs the attached function on the thread that completes the result (`Runnable::run`). The functions are tiny (add a header, write a log line), so a thread handoff would cost more than the work.

**One limit.** A filter written this way can't wait for something asynchronous *before* deciding whether to call the next action. Lattice's six don't need to: `RequiredActionsFilter` reads the session synchronously.

**What was verified and what was inferred.** The profile showed the stream creation called from `Accumulator.futureToSink`, and the throughput after the change confirmed it (health from about 30,000 to 52,000–64,000 requests a second). Why a plain `Filter` has to start a stream comes from reading Play's design, and the source wasn't stepped through. That the shared parent actor handled the creations one at a time, which would explain the ceiling near 30,000, is an interpretation of what `ChildrenContainer` showed in the profile.

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

## Looking at the pages in a browser

The load-test server is also the quickest way to see Lattice's pages without Authlete credentials: it is the whole application with a scripted Authlete behind it.

```sh
java -cp "$(perf/classpath.sh)" com.lattice.oidc.perf.PerfServer
```

It listens on http://localhost:9000 and stops after 30 minutes (`PERF_SERVER_SECONDS`). Storage is in memory, so everything is lost when it stops. The demo accounts are `john`, `jane`, `max` and `inga`, each with its own name as the password. `john` is the operator.

What the scripted Authlete does: it answers discovery and the key set, hands out one authorization request (the app "Acme Notes", client 42, with `openid` and `profile`), returns a stock "issued" answer when consent is approved and remembers the approval for that user (it then shows under connected apps on the account page, and "Remove access" forgets it), and serves two clients to the operator console ("Acme Notes", and "Living Room TV", registered dynamically). It doesn't script the token endpoint, so `POST /api/token` answers `500 server_error`, and nothing that needs real tokens works.

| Page | URL |
| --- | --- |
| Home | `/` |
| Sign-in and consent for an authorization request | `/api/authorization?response_type=code&client_id=42` |
| Account (sign-in first) | `/account` |
| Active sessions, sign out everywhere | `/account/sessions`, `/account/sessions/others` |
| Change password | `/account/password` |
| Two-step verification | `/account/two-step` |
| Required actions after sign-in | `/account/actions` |
| Forgot password | `/account/recover` |
| Device flow: enter a code | `/api/device/verification` |
| Sign out (RP-initiated logout) | `/api/logout` |
| Credential offer form | `/api/offer/issue` |
| Passkey failed page | `/passkeys/failed` |
| Operator console: clients (all, or `?registration=dynamic`) | `/admin/clients` |
| Operator console: one client, secret rotation | `/admin/clients/42`, `/admin/clients/43` |
| Operator console: audit log, security overview | `/admin/audit`, `/admin/security` |
| Health, metrics | `/health/live`, `/health/ready`, `/health/dependencies`, `/metrics` |
| Discovery, keys | `/.well-known/openid-configuration`, `/api/jwks` |

Not reachable here: the built-in CIBA approval page `/ciba` (404 unless `lattice.ciba.mode` is `builtin`), and the reset, email-verification and passkey-created pages, which need a real link or a finished flow. The stylesheets and scripts under `/assets/` are on the classpath because `perf/classpath.sh` adds `public/`; sbt adds it itself only for `run` and `stage`.
