# HAProxy in front of Lattice

[haproxy.cfg](haproxy.cfg) is a production configuration for HAProxy 3.2 or newer. It takes the place
of Caddy in the Compose setup when you run your own load balancer: TLS, several Lattice servers,
mutual TLS for OAuth clients, per-client limits and health checks. Every setting in it is
commented with why it's there.

**For a development machine** without certificates, use [haproxy-local.cfg](haproxy-local.cfg) instead:
plain HTTP on `127.0.0.1:9080` in front of Lattice on port 9000, with the same header cleaning,
request IDs, logging and health checks, and no HTTPS or mutual-TLS port. Its first lines show how to
install it with Homebrew.

## What it does

| Port | What it serves |
|---|---|
| 80 | Redirects everything to HTTPS (`308`, which keeps the method and body). |
| 443 (TCP and UDP) | Lattice over HTTP/1.1, HTTP/2 and HTTP/3 (QUIC). Never asks for a client certificate. |
| 8443 | The OAuth endpoints for clients that authenticate with a TLS certificate (RFC 8705). |
| 127.0.0.1:8404 | HAProxy's own Prometheus metrics (`/metrics`) and stats page (`/stats`). |

On the way to Lattice it:
- **Replaces** `X-Forwarded-For` and `X-Forwarded-Proto` with the real client address and `https`,
  and removes `Forwarded`, so nothing a client sends in these headers reaches Lattice.
- **Removes every client certificate header** a client could send (`Client-Cert`, `X-Ssl-Cert`,
  `X-Client-Cert`, `X-Forwarded-Client-Cert-Pem`, `X-Ssl-Cert-Chain-*`). On port 8443 it then adds
  the certificate the client actually presented, as `Client-Cert: :<base64 DER>:` (RFC 9440).
- **Keeps a client's `X-Request-ID`** if Lattice would accept it (letters, digits, `._:-`, up to 64
  characters), otherwise sets a new UUIDv7. HAProxy's log and Lattice's show the same ID.
- **Refuses** `/metrics` (404), bodies over 1 MiB (413), more than 500 requests per 10 seconds or
  200 open connections from one address (429, or the connection is closed). Its own errors are
  JSON, as OAuth clients expect.
- **Logs each request's path without its query string**, because OAuth URLs carry authorization
  codes, `state` and `id_token_hint`.
- **Balances** to the server with the fewest open requests, checks `/health/live` every 2 seconds,
  and lets a restarted server warm up over 30 seconds.

## Settings Lattice needs

| Setting | Value | Why |
|---|---|---|
| `play.http.forwarded.trustedProxies` ([production.conf](../config/production.conf)) | Must include HAProxy's address | Otherwise Lattice ignores `X-Forwarded-For` and `X-Forwarded-Proto`. The default lists the private ranges; add `127.0.0.1` if HAProxy runs on the same host. |
| `PUBLIC_BASE_URL` | `https://<your host>` | Lattice builds URLs (DPoP `htu`, redirects) from it, not from headers. |
| `MTLS_TRUST_PROXY_HEADERS` | `true` only if you use port 8443 | Lattice then reads the client certificate from `Client-Cert`. |

**Only HAProxy may reach Lattice** once `MTLS_TRUST_PROXY_HEADERS` is on. HAProxy removes forged
certificate headers, but a client that can reach a Lattice server directly could send its own and
claim to be any client. Keep Lattice on a private network, or behind a firewall that only lets
HAProxy in.

For port 8443, tell clients where it is: set the `mtls_endpoint_aliases` of the Authlete service to
the `:8443` URLs of the token, PAR, revocation, introspection, device authorization, CIBA and
UserInfo endpoints. Lattice's discovery document then lists them.

## Install it

1. **Certificates:** one PEM file per host name in `/etc/haproxy/certs/`, each holding the
   certificate, its chain and its private key (`cat cert.pem chain.pem key.pem > host.pem`).
   HAProxy picks one by SNI. Get them from your CA or certbot, and reload HAProxy when they change.
2. **Client CA** (only for port 8443): `/etc/haproxy/client-ca.pem`, the CAs whose certificates
   clients should offer. Self-signed client certificates still work; Lattice checks them against
   each client's registration.
3. **Servers:** replace the two `server` lines in `backend lattice` with your Lattice servers.
4. **Check and load:**

   ```sh
   haproxy -c -f /etc/haproxy/haproxy.cfg
   systemctl reload haproxy        # reloads without dropping connections
   ```

The paths can be changed without editing the file, through the environment:
`LATTICE_CERTS`, `LATTICE_CLIENT_CA` and `HAPROXY_RUN` (the directory of the admin socket).

**On macOS** (`brew services`), Homebrew's service runs
`haproxy -f /opt/homebrew/etc/haproxy.cfg` without these variables, so change the three
`presetenv` paths at the top of the file to folders under `/opt/homebrew/etc/haproxy/`. The
`quic` lines print a warning on macOS, which lacks the socket option HAProxy uses for UDP on Linux;
remove them there.

### How `brew services` runs HAProxy on macOS

`brew services` is a front end for **launchd**, macOS's service manager (process 1, like systemd
on Linux). `brew services start haproxy` writes `~/Library/LaunchAgents/sh.brew.haproxy.plist`
and asks launchd to load it, so HAProxy runs as you and starts when you log in. With
`sudo brew services start haproxy`, the file goes to `/Library/LaunchDaemons/` instead, so the
service runs as root and starts at boot, before anyone logs in.

launchd reads service files from these folders:

| Folder | For | Runs as | Started when |
|---|---|---|---|
| `~/Library/LaunchAgents/` | You only (`brew services start`) | You | You log in |
| `/Library/LaunchAgents/` | Every user of the Mac (needs an admin to install) | Each user who logs in | They log in |
| `/Library/LaunchDaemons/` | The whole Mac (`sudo brew services start`) | Root | The Mac starts |
| `/System/Library/LaunchAgents/` | Apple's own services, per user | Each user who logs in | They log in |
| `/System/Library/LaunchDaemons/` | Apple's own services, for the whole Mac | Root | The Mac starts |

The two `/System/Library/` folders are for Apple's services only. They are on macOS's sealed system
volume, read-only even for root while System Integrity Protection is on, and only macOS updates
change them. Your own services go in one of the first three.

For example, on a Mac with two accounts, `harmony` and `guest`:
- **`~/Library/LaunchAgents/sh.brew.haproxy.plist`** (for `harmony`, that's
  `/Users/harmony/Library/LaunchAgents/...`): HAProxy starts when `harmony` logs in. When `guest`
  logs in, nothing happens.
- **The same file in `/Library/LaunchAgents/`:** HAProxy starts for both. With both logged in at
  once (fast user switching), two copies run, one as `harmony` and one as `guest`.
- **The same file in `/Library/LaunchDaemons/`:** one copy for the whole Mac, as root, from boot,
  whether or not anyone has logged in.

So on a single-user Mac, `~/Library/LaunchAgents/` is the right place for anything you run for
yourself. `/Library/LaunchAgents/` is mainly for software that every account on a shared Mac should
get.

Only the service file is in these folders. The program, its configuration and its logs stay under
`/opt/homebrew` (for HAProxy: `opt/haproxy`, `etc/haproxy.cfg`, `var/log/haproxy.log`).

The `.plist` file says what launchd does:

| Key | In Homebrew's HAProxy service | Effect |
|---|---|---|
| `ProgramArguments` | `haproxy -f /opt/homebrew/etc/haproxy.cfg` | The command that runs |
| `RunAtLoad` | `true` | Starts as soon as it's loaded, at every login |
| `KeepAlive` | `true` | Restarted whenever it exits, even after an error |
| `StandardOutPath`, `StandardErrorPath` | `/opt/homebrew/var/log/haproxy.log` | Where its output and errors go |

Because of `KeepAlive`, a broken configuration doesn't stop the service: launchd starts HAProxy, it
exits with an error, and launchd tries again. `brew services` then shows `error 1`, and the reason is
in the log:

```sh
brew services                                   # status of every Homebrew service
tail -5 /opt/homebrew/var/log/haproxy.log       # the error, e.g. a missing configuration file
launchctl print gui/$(id -u)/sh.brew.haproxy    # launchd's view: state, last exit code, paths
```

Use `brew services start`, `stop` and `restart` rather than `launchctl` directly, so Homebrew's
list stays in sync with launchd.
