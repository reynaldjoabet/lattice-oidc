# Deploying Lattice

Both setups run the Docker image that sbt-native-packager builds from this repository. [The README's Docker image section](../README.md#docker-image) explains what's in the image: a non-root user, read-only files, `tini`, and logs to stdout.

```sh
sbt --client Docker/publishLocal                       # local image: lattice-oidc:<version>
DOCKER_REGISTRY=ghcr.io DOCKER_USERNAME=<you> \
  sbt --client Docker/publish                          # push amd64 + arm64 for Kubernetes
```

| Path | What it is |
| --- | --- |
| [config/production.conf](config/production.conf) | Production settings for both setups: trusted proxies, allowed host, PostgreSQL and Redis, secure cookies, HSTS, no demo users. Loaded with `-Dconfig.file`. |
| [compose/](compose/) | One host: Caddy (TLS) → Lattice → PostgreSQL and Valkey, with optional Prometheus and Grafana. |
| [kubernetes/base/](kubernetes/base/) | Deployment, Service, PodDisruptionBudget, autoscaler, NetworkPolicy, ServiceAccount and namespace. |
| [kubernetes/overlays/production/](kubernetes/overlays/production/) | One environment: image, host name, settings, secrets, Gateway API route, optional ServiceMonitor. |

## What both setups need

- **A public host name over HTTPS.** Passkeys are bound to it, and the session cookie is HTTPS-only.
- **The secrets.** The application secret, the pairwise and second-factor keys, Authlete's service ID and token, the database and Redis passwords, and the metrics token. Generate each one separately, for example with `openssl rand -hex 32`. Three of them must never change casually:
  - `PAIRWISE_SECRET` changes every pairwise `sub`.
  - `SECOND_FACTOR_ENCRYPTION_KEY` makes users set up their authenticator app again, unless you rotate it with `SECOND_FACTOR_PREVIOUS_ENCRYPTION_KEYS`.
  - `APPLICATION_SECRET` signs everyone out.
- **`RS0_SECRET`.** The built-in introspection client `rs0` otherwise uses the secret written in `application.conf`.
- **Trusted proxies that match your network.** See [Behind a proxy](#behind-a-proxy-client-ips-and-allowed-hosts).

## Behind a proxy: client IPs and allowed hosts

### Which IP address Lattice sees

**Without a proxy,** Alice's browser connects straight to Lattice, so the connection's source address is her real IP:

```
Alice (203.0.113.7) ──────────────► Lattice
                                    request.remoteAddress() = 203.0.113.7  ✓
```

**With a proxy** (Caddy, or a Kubernetes gateway), Alice connects to the proxy, and the proxy opens a new connection to Lattice. The connection Lattice sees comes from the proxy:

```
Alice (203.0.113.7) ──► Caddy (172.18.0.2) ──► Lattice
                        adds header:            connection comes from 172.18.0.2
                        X-Forwarded-For: 203.0.113.7
```

The proxy writes Alice's real IP into the `X-Forwarded-For` header. Play reads that header only if the connection comes from an address in `play.http.forwarded.trustedProxies`. Play's default trusts only `127.0.0.1` and `::1`. Caddy's address isn't in that list, so without a fix Play ignores the header and reports the proxy's address for everyone:

```
Alice   (203.0.113.7)  → remoteAddress = 172.18.0.2
Bob     (198.51.100.4) → remoteAddress = 172.18.0.2
Mallory (192.0.2.66)   → remoteAddress = 172.18.0.2
```

Lattice limits failed sign-ins per IP address, so this would make everyone share one counter. Five wrong passwords for `alice` from anyone would lock out the real Alice. Fifty failures across any accounts would block every user for the lockout period. The audit log would also show the same address for every event.

**The fix,** in [config/production.conf](config/production.conf):

```hocon
play.http.forwarded.trustedProxies = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"]
```

Caddy's 172.18.0.2 is inside `172.16.0.0/12`, so Play now uses the header, and Alice is 203.0.113.7 again.

Why trust only proxies, rather than the header from anyone? Because anyone can send it. An attacker could set a different fake `X-Forwarded-For` on every attempt and never hit a per-IP limit. Play believes the header only when the connection comes from a trusted proxy. It then reads the header right to left, skipping trusted addresses, and takes the first untrusted one, which is the address the proxy saw.

Trusting whole private ranges is safe only while nothing else on those networks can reach Lattice directly. Both setups ensure that:
- **Compose:** Lattice publishes no port, so only Caddy reaches it.
- **Kubernetes:** the NetworkPolicy admits only the gateway's and Prometheus's namespaces.

If you know your proxy's or pod network's exact range, narrow the list to it.

### The allowed-hosts filter and the probes

**What the filter does.** Every HTTP request carries a `Host` header naming the site it was sent to. Play's `AllowedHostsFilter` returns 400 Bad Request when that header isn't on the allowed list. In production, `production.conf` limits the list to your host name (`ALLOWED_HOST`):

```
GET /login   Host: login.example.com  → allowed
GET /login   Host: evil.example       → 400 Bad Request
```

This blocks Host header attacks. Suppose an app builds links from the `Host` header. An attacker requests a password reset for Alice with `Host: evil.example`, and the email Alice receives then contains a reset link to `evil.example`, a site the attacker controls.

**The problem: probes and Prometheus use the pod's IP.** Kubernetes checks each pod by sending it a request directly, addressed by the pod's IP:

```
GET /health/live   Host: 10.244.1.17:9000
```

`10.244.1.17:9000` isn't on the allowed list, so the filter would answer 400, and Kubernetes would treat that as "the app is broken":
1. The liveness probe fails, so Kubernetes restarts the pod.
2. The new pod gets the same 400, so it's restarted again, in an endless loop.
3. The readiness probe fails too, so the pod never receives traffic.

Prometheus has the same problem: it scrapes `/metrics` on each pod by IP. The pod IPs can't go on the allowed list, because they change every time a pod restarts. Allowing every host (`"."`) would switch off the protection for the whole site.

**The fix.** Play lets individual routes opt out of the filter with a route modifier. In [conf/routes](../conf/routes), these three routes carry `+ anyhost`:

```
+ anyhost
GET     /health/live    ...
+ anyhost
GET     /health/ready   ...
+ anyhost
GET     /metrics        ...
```

```
GET /health/live   Host: 10.244.1.17:9000  → 200 (exempt)
GET /login         Host: 10.244.1.17:9000  → 400 (still checked)
```

This is safe because these three responses never use the `Host` header: they return "UP", or a list of numbers. Every page where the host name matters, such as sign-in, password reset and the OIDC endpoints, is still checked.

## Docker Compose

```sh
cd deploy/compose
cp .env.example .env && chmod 600 .env   # fill in every value
docker compose up -d                      # Caddy, Lattice, PostgreSQL, Valkey
docker compose --profile monitoring up -d # also Prometheus and Grafana (127.0.0.1:3000)
```

The DNS record for `LATTICE_DOMAIN` must point at the host, with ports 80 and 443 open, so Caddy can get the certificate.

- **Network layout:** only Caddy publishes ports. Lattice has no published port, and PostgreSQL, Valkey and Prometheus sit on an internal network with no route to the internet.
- **Hardening:** every container that allows it runs with a read-only filesystem, all capabilities dropped and `no-new-privileges`.
- **Health checks and start order:** Lattice starts only when PostgreSQL and Valkey are healthy, and Caddy only when Lattice is. Lattice's health check uses bash's `/dev/tcp`, because the image has no curl.
- **Limits:** memory limits are set, and the JVM heap follows the 1 GB limit. Logs rotate at 5 × 10 MB per container.
- **`/metrics`:** Caddy answers 404 for it. Prometheus scrapes Lattice directly, with the bearer token passed as a Compose secret.
- **Valkey:** an open-source fork of Redis, holding only short-lived state, so nothing is persisted. A restart loses pending sign-ins and rate-limit counters, never accounts or sessions.
- **Backups:** back up the `postgres-data` volume, for example with `docker compose exec postgres pg_dump -U lattice lattice`. Caddy's certificates are in `caddy-data`.

## Kubernetes

```sh
cd deploy/kubernetes/overlays/production
cp secrets.env.example secrets.env && chmod 600 secrets.env   # fill it in
# edit kustomization.yaml: image, host name, DATABASE_URL; httproute.yaml: Gateway and host
kubectl apply -k .
```

**Prerequisites:**
- **Kubernetes 1.30 or newer,** for the `preStop` sleep action.
- **A CNI that enforces NetworkPolicy,** such as Calico or Cilium.
- **A Gateway API implementation,** with a Gateway that has an HTTPS listener for the host name.
- **PostgreSQL and Redis.** These manifests deliberately don't run databases. Use a managed service, or an operator such as CloudNativePG (its `<cluster>-rw` Service is what the example `DATABASE_URL` points at), and any Redis-compatible service.

**What the base sets up:**
- **Security:** a namespace that enforces the `restricted` Pod Security Standard, and a ServiceAccount with no API token. The pod runs as UID 1001 with a read-only root filesystem, no capabilities and the default seccomp profile, and `/tmp` is an `emptyDir`.
- **Probes:**
  - A startup probe gives the JVM and Flyway's migrations three minutes.
  - Liveness uses `/health/live`.
  - Readiness uses `/health/ready`, which also checks that Authlete answers.
- **Availability:**
  - 3 to 10 replicas, autoscaled at 70% of the CPU request, scaling down slowly.
  - Rollouts never go below the current capacity.
  - Replicas spread across nodes, and across zones when the cluster has them.
  - A PodDisruptionBudget lets drains take one replica at a time.
  - A 10-second `preStop` pause lets endpoint removal reach the gateway before shutdown.
- **Resources:** 500m CPU and 1 GiB memory requested, and a 1 GiB memory limit. There is no CPU limit, because throttling a JVM stalls its garbage collector.
- **NetworkPolicy:** traffic in only from the gateway and monitoring namespaces (change the two namespace names to yours). Traffic out only for DNS, PostgreSQL, Redis and HTTPS, plus LDAPS and mail submission.
- **Config changes:** generated ConfigMaps and Secrets have a hash in their name, so changing `production.conf`, a setting or a secret rolls the Deployment.

**Database connections:** every replica opens up to `DATABASE_POOL_SIZE` connections (10). At the autoscaler's maximum of 10 replicas that's 100, so size PostgreSQL's `max_connections` accordingly. Flyway takes a PostgreSQL advisory lock, so replicas starting together migrate the schema only once.

**Secrets:** `secretGenerator` reads `secrets.env`, which suits a start. For production, prefer the External Secrets Operator, Sealed Secrets or a CSI secrets driver, creating a Secret named `lattice-secrets`, and delete the generator.

**Monitoring:** with the Prometheus Operator installed, uncomment `servicemonitor.yaml` in the overlay. It scrapes `/metrics` with the token from `lattice-secrets`. The HTTPRoute rewrites public requests for `/metrics` to a path that returns 404.

## Checks run on these files

- `docker compose config` with placeholder values: valid, and it fails with a clear message when a required value is missing.
- `kubectl kustomize` on the overlay: renders, with every ConfigMap and Secret reference resolved to its hashed name.
- `kubeconform -strict` against Kubernetes 1.34, including the Gateway API and Prometheus Operator schemas: all 12 resources valid.

Not yet run: starting either setup against real Authlete credentials.
