# HAProxy in front of Lattice

[haproxy.cfg](haproxy.cfg) is a production configuration for HAProxy 3.2 or newer. It takes the place
of Caddy in the Compose setup when you run your own load balancer: TLS, several Lattice servers,
mutual TLS for OAuth clients, per-client limits and health checks. Every setting in it is
commented with why it's there.

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

## How it was tested

With HAProxy 3.4.7, a self-signed server certificate and a stub backend that echoes the headers it
receives (on local ports, with the rate limit lowered to 40 to keep the test short):

| Check | Result |
|---|---|
| `haproxy -c` | Valid. The only warning is the macOS QUIC one above. |
| `http://` | `308` to `https://` |
| Forged `X-Forwarded-For`, `Forwarded`, `X-Forwarded-Proto`, `Client-Cert`, `X-Ssl-Cert`, `X-Ssl-Cert-Chain-1` on port 443 | Lattice sees the real address and `https`, and no certificate header |
| `X-Request-ID: trace-123.abc:9` / `X-Request-ID: bad id <script>` | Kept / replaced with a UUIDv7 |
| `/metrics`, a 2 MB body | `404`, `413` |
| 45 requests from one address | 33 `200`, then `429` with `{"error":"too_many_requests",...}` (the earlier checks counted too) |
| HTTP/2 | Negotiated |
| Port 8443 with a client certificate, plus forged certificate headers | `Client-Cert` is exactly the presented certificate, as `:<base64 DER>:`; the forged headers are gone |
| Port 8443 without a certificate, with forged headers | No certificate header reaches Lattice |
| Port 8443, `/account/login` | `404` |
| A request to `/cb?code=SECRET-CODE` | Logged as `GET "/cb"`; the code isn't in the log |
| `127.0.0.1:8404/metrics` | Prometheus metrics |

Not tested here: HTTP/3 (macOS), several Lattice servers, and the real Lattice behind it.

macOS's built-in `curl` can't complete the handshake on port 8443 ("decode error"): it fails when a
server asks for an optional client certificate. `openssl s_client` and other clients work.
