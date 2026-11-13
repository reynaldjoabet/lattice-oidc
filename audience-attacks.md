# Audience attacks: two fixes, with worked examples

A token's audience (`aud`) says who the token is for. If the receiver doesn't check that it is
the intended audience, a token made for someone else can be replayed to it. Lattice closes two
such gaps:

1. [Client assertions whose audience isn't Lattice's issuer](#1-client-assertions-rfc-10070), from RFC 10070 (November 2026).
2. [ID tokens exchanged by a client they weren't issued to](#2-id-tokens-in-token-exchange-rfc-8693), in token exchange (RFC 8693).

Every example is an HTTP request followed by the response to it. Where it matters, the response
is shown twice: from a server without the check (**before**) and from Lattice now (**after**).

The examples use these names:

| Name | What it is |
|---|---|
| `lattice.example` | Lattice, the honest authorization server. Issuer identifier: `https://lattice.example` |
| `evil.example` | An authorization server run by the attacker |
| `https://wallet.example` | A client of both servers, with this same client ID at each |
| `banking-app`, `recipes-app` | Two clients registered at Lattice |

Tokens and assertions are shortened (`eyJ...`). Where their content matters, it is shown
decoded below the message, as header and payload; signatures are left out.

---

## 1. Client assertions (RFC 10070)

### The rule

With `private_key_jwt` (or `client_secret_jwt`), a client authenticates with a JWT it signed,
the *client assertion*. A normal request and response:

```http
POST /api/token HTTP/1.1
Host: lattice.example
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials
&client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer
&client_assertion=eyJhbGciOiJFUzI1NiIsInR5cCI6ImNsaWVudC1hdXRoZW50aWNhdGlvbitqd3QifQ...
```

```http
HTTP/1.1 200 OK
Content-Type: application/json
Cache-Control: no-store

{"access_token":"eyJ...","token_type":"Bearer","expires_in":3600}
```

The assertion, decoded:

```json
{ "alg": "ES256", "typ": "client-authentication+jwt" }
{
  "iss": "https://wallet.example",
  "sub": "https://wallet.example",
  "aud": "https://lattice.example",
  "jti": "4b1c7e0a-6f5e-4c0e-9d1a-2f1d3c9e8a71",
  "exp": 1794000060
}
```

RFC 7523 and RFC 9126 used to let the audience be the issuer, the token endpoint URL or the PAR
endpoint URL, and servers accepted any of them. RFC 10070 removes that choice: **`aud` must be
the server's issuer identifier, and nothing else.** Servers must refuse anything else.

### The attack: audience injection

A client learns about an authorization server from its metadata. RFC 8414 makes the client
check one value: that `issuer` matches the URL it fetched the metadata from. The other values,
such as `token_endpoint`, can't be checked, because a server may put its endpoints on any host.
Hosseyni, Küsters and Würtele showed how an attacker exploits that ("Audience Injection
Attacks", IACR ePrint 2025/629, the research RFC 10070 cites).

**What the attacker needs:** the wallet is a client of both Lattice and the attacker's server,
under the same client ID. That's common where client IDs are URLs, as in OpenID Federation and
wallet ecosystems.

**Step 1.** The wallet reads the attacker's metadata. `issuer` is honest; `token_endpoint` is
Lattice's:

```http
GET /.well-known/oauth-authorization-server HTTP/1.1
Host: evil.example
```

```http
HTTP/1.1 200 OK
Content-Type: application/json

{
  "issuer": "https://evil.example",
  "token_endpoint": "https://lattice.example/api/token",
  "pushed_authorization_request_endpoint": "https://evil.example/par"
}
```

The wallet accepts it: `issuer` matches the URL it fetched.

**Step 2.** The wallet makes a pushed authorization request to the attacker's server. As the
old rules allowed, it uses the token endpoint URL as the assertion's audience:

```http
POST /par HTTP/1.1
Host: evil.example
Content-Type: application/x-www-form-urlencoded

response_type=code
&client_id=https%3A%2F%2Fwallet.example
&redirect_uri=https%3A%2F%2Fwallet.example%2Fcb
&code_challenge=Qm9vay1vZi1zcGVsbHM&code_challenge_method=S256
&client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer
&client_assertion=eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJodHRwczovL3dhbGxldC5leGFtcGxlIi...
```

```http
HTTP/1.1 201 Created
Content-Type: application/json

{"request_uri":"urn:ietf:params:oauth:request_uri:6esc_11ACC5bwc014ltc14eY22c","expires_in":60}
```

The attacker answers normally, so the wallet notices nothing. It now holds this assertion,
signed by the wallet:

```json
{ "alg": "ES256" }
{
  "iss": "https://wallet.example",
  "sub": "https://wallet.example",
  "aud": "https://lattice.example/api/token",
  "jti": "9e2d5a10-1c3b-4f7e-8a2d-6b0c4e1f3a95",
  "exp": 1794000060
}
```

**Step 3.** Before the assertion expires, the attacker replays it to Lattice as the wallet:

```http
POST /api/token HTTP/1.1
Host: lattice.example
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials
&client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer
&client_assertion=eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJodHRwczovL3dhbGxldC5leGFtcGxlIi...
```

**Before**, from a server following the rules before RFC 10070: the signature is the wallet's,
the assertion is unexpired, its `jti` is new here, and the token endpoint URL was a valid
audience. The attacker gets tokens as `https://wallet.example`:

```http
HTTP/1.1 200 OK
Content-Type: application/json
Cache-Control: no-store

{"access_token":"eyJ...","token_type":"Bearer","expires_in":3600}
```

Lattice didn't check the audience itself; it left that to Authlete. The same replay works at
the PAR, revocation, device authorization and CIBA endpoints, wherever the wallet's assertion
is accepted.

**After**, from Lattice now:

```http
HTTP/1.1 401 Unauthorized
Content-Type: application/json
Cache-Control: no-store

{"error":"invalid_client","error_description":"The client assertion's audience must be the issuer identifier, and only it."}
```

**Why this stops it:** a client following RFC 10070 puts the issuer in `aud`. In step 2 that's
`https://evil.example`, the only value the wallet checked. The attacker can't make it say
`https://lattice.example`: the wallet only uses that issuer with metadata fetched from Lattice.

### Which assertions Lattice accepts

`ClientAssertionAudience` checks every JWT client assertion at the token, PAR, revocation,
device authorization and CIBA endpoints, before Authlete is called. The audience must be
exactly Lattice's issuer, as the only value, compared character for character:

| `aud` in the client assertion | Lattice's response |
|---|---|
| `"https://lattice.example"` | Passed to Authlete, which checks signature, expiry and replay |
| `"https://lattice.example/api/token"` | `401 invalid_client` |
| `"https://lattice.example/api/par"` | `401 invalid_client` |
| `["https://lattice.example", "https://other.example"]` | `401 invalid_client` |
| `"https://lattice.example/"` (trailing slash) | `401 invalid_client` |
| missing | `401 invalid_client` |

Not affected:
- **The JWT authorization grant** (`grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer`).
  Its `assertion` may still name the token endpoint, as RFC 10070 allows for grants.
- **The `typ` header.** Clients should send `typ: client-authentication+jwt`, but RFC 10070
  recommends that servers don't refuse assertions without it, so Lattice doesn't.

### Check it

The same request with each audience. With `aud: "https://lattice.example/api/token"`:

```http
POST /api/token HTTP/1.1
Host: lattice.example
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials
&client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer
&client_assertion=eyJ...(aud: https://lattice.example/api/token)
```

```http
HTTP/1.1 401 Unauthorized
Content-Type: application/json
Cache-Control: no-store

{"error":"invalid_client","error_description":"The client assertion's audience must be the issuer identifier, and only it."}
```

With `aud: "https://lattice.example"`:

```http
POST /api/token HTTP/1.1
Host: lattice.example
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials
&client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer
&client_assertion=eyJ...(aud: https://lattice.example)
```

```http
HTTP/1.1 200 OK
Content-Type: application/json
Cache-Control: no-store

{"access_token":"eyJ...","token_type":"Bearer","expires_in":3600}
```

Tests: `ClientAssertionAudienceTest` (the rule) and `ClientAssertionAudienceEndpointsTest` (the
endpoints refuse before Authlete is called, and the logging mode).

### Rolling it out

Clients still using the token endpoint as audience get `401 invalid_client` once this is
deployed. To find them first, set `CLIENT_ASSERTION_STRICT_AUDIENCE=false`
(`lattice.client-assertion.strict-audience`). Their requests then succeed as before, and each
is logged:

```text
WARN  c.l.o.s.ClientAssertionAudience  Accepted a client assertion from client https://wallet.example although its audience is [https://lattice.example/api/token], not exactly [https://lattice.example] (strict-audience is off)
```

When the warnings stop, remove the setting.

---

## 2. ID tokens in token exchange (RFC 8693)

### The rule

An ID token is a statement from the authorization server **to one client**: "this user signed
in to you". Its `aud` is that client's ID; `azp`, when present, is the client that requested
it. It isn't a credential for any other client.

Token exchange lets a client trade a token it holds for a new access token. Lattice checked an
ID token's signature, issuer and expiry, but not who it was issued to.

### The attack

**What the attacker needs:** a client allowed to use token exchange (`recipes-app`), and an
ID token Lattice issued to another client for the victim. ID tokens aren't handled as secrets,
so they leak more easily than access tokens. Examples:
- **Logout URLs:** they're the `id_token_hint` of RP-initiated logout, which lands in browser
  history, proxy logs and analytics.
- **Front-channel responses:** hybrid and implicit flows put them in the URL fragment.
- **Front ends and logs:** apps hand them to JavaScript, or log them for debugging.

**Step 1.** Alice signs out of `banking-app`. The browser follows this logout URL, and the
attacker later finds it in a log:

```http
GET /api/logout?id_token_hint=eyJhbGciOiJSUzI1NiIsImtpZCI6IjEifQ.eyJpc3MiOiJodHRwczovL2xhdHRpY2UuZXhhbXBsZSIsInN1YiI6IjEwMDEiLCJhdWQiOiJiYW5raW5nLWFwcCJ9...&post_logout_redirect_uri=https%3A%2F%2Fbank.example%2Fbye HTTP/1.1
Host: lattice.example
```

```http
HTTP/1.1 302 Found
Location: https://bank.example/bye
Cache-Control: no-store
```

The `id_token_hint`, decoded:

```json
{ "alg": "RS256", "kid": "1" }
{
  "iss": "https://lattice.example",
  "sub": "1001",
  "aud": "banking-app",
  "azp": "banking-app",
  "auth_time": 1794000000,
  "exp": 1794000300
}
```

**Step 2.** `recipes-app` exchanges Alice's ID token, authenticating as itself:

```http
POST /api/token HTTP/1.1
Host: lattice.example
Authorization: Basic cmVjaXBlcy1hcHA6c2VjcmV0
Content-Type: application/x-www-form-urlencoded

grant_type=urn:ietf:params:oauth:grant-type:token-exchange
&subject_token=eyJhbGciOiJSUzI1NiIsImtpZCI6IjEifQ.eyJpc3MiOiJodHRwczovL2xhdHRpY2UuZXhhbXBsZSIsInN1YiI6IjEwMDEiLCJhdWQiOiJiYW5raW5nLWFwcCJ9...
&subject_token_type=urn:ietf:params:oauth:token-type:id_token
&scope=profile%20email
```

**Before**, the signature, issuer and expiry were valid, so Lattice issued `recipes-app` an
access token **for Alice** (`sub: 1001`):

```http
HTTP/1.1 200 OK
Content-Type: application/json
Cache-Control: no-store

{"access_token":"eyJ...","issued_token_type":"urn:ietf:params:oauth:token-type:access_token","token_type":"Bearer","expires_in":3600}
```

**Step 3.** With that token, `recipes-app` acts as Alice at any API that trusts Lattice's
tokens, although she never signed in to it or consented:

```http
GET /api/userinfo HTTP/1.1
Host: lattice.example
Authorization: Bearer eyJ...
```

```http
HTTP/1.1 200 OK
Content-Type: application/json

{"sub":"1001","name":"Alice Example","email":"alice@example.com","email_verified":true}
```

**After**, from Lattice now, step 2 is refused:

```http
HTTP/1.1 400 Bad Request
Content-Type: application/json
Cache-Control: no-store

{"error":"invalid_request","error_description":"The ID token was not issued to this client."}
```

The same applies to ID tokens from a configured trusted issuer (`lattice.trusted-jwt-issuers`).

### Which ID tokens a client can exchange

An ID token is exchanged only by the client it was issued to. `aud` must include the requesting
client's ID or its client ID alias at Lattice, and `azp`, if present, must name that client too:

| ID token | Exchanged by | Lattice's response |
|---|---|---|
| `aud: "banking-app"` | `banking-app` | `200 OK`, new access token |
| `aud: "banking-app"` | the client whose alias is `banking-app` | `200 OK` |
| `aud: "banking-app"` | `recipes-app` | `400 invalid_request` |
| `aud: ["banking-app", "recipes-app"]`, `azp: "banking-app"` | `recipes-app` | `400 invalid_request` |
| no `aud` | any client | `400 invalid_request` |

Not affected:
- **Subject tokens of type `jwt`** (`urn:ietf:params:oauth:token-type:jwt`). A general JWT's
  audience is often an API, not a client, so it keeps the signature, issuer and expiry checks.
- **Access and refresh tokens Lattice issued:** Authlete validates those.
- **Native SSO,** where a second app presents the first app's ID token with the device
  secret: Authlete reports it as a separate action, handled by its own code.

### Check it

`banking-app` exchanging its own ID token:

```http
POST /api/token HTTP/1.1
Host: lattice.example
Authorization: Basic YmFua2luZy1hcHA6c2VjcmV0
Content-Type: application/x-www-form-urlencoded

grant_type=urn:ietf:params:oauth:grant-type:token-exchange
&subject_token=eyJ...(aud: banking-app)
&subject_token_type=urn:ietf:params:oauth:token-type:id_token
```

```http
HTTP/1.1 200 OK
Content-Type: application/json
Cache-Control: no-store

{"access_token":"eyJ...","issued_token_type":"urn:ietf:params:oauth:token-type:access_token","token_type":"Bearer","expires_in":3600}
```

`recipes-app` exchanging the same ID token:

```http
POST /api/token HTTP/1.1
Host: lattice.example
Authorization: Basic cmVjaXBlcy1hcHA6c2VjcmV0
Content-Type: application/x-www-form-urlencoded

grant_type=urn:ietf:params:oauth:grant-type:token-exchange
&subject_token=eyJ...(aud: banking-app)
&subject_token_type=urn:ietf:params:oauth:token-type:id_token
```

```http
HTTP/1.1 400 Bad Request
Content-Type: application/json
Cache-Control: no-store

{"error":"invalid_request","error_description":"The ID token was not issued to this client."}
```

Tests: `IdTokenAudienceTest` (the rule, including `azp`) and the `exchangeOfAnIdToken...` tests
in `TokenGrantsTest` (the endpoint, the alias and the logging mode).

### Rolling it out

To find exchanges that would be refused, set `TOKEN_EXCHANGE_STRICT_ID_TOKEN_AUDIENCE=false`
(`lattice.token-exchange.strict-id-token-audience`). They then succeed as before, and each is
logged:

```text
WARN  c.l.oidc.handlers.TokenGrantHandler  Exchanged an ID token for client 77 although it was issued to [banking-app] (strict-id-token-audience is off)
```

To exchange an ID token another provider issued to the client under a different ID, make that
ID the client's alias at Lattice.

---

## References

- RFC 10070, Updates to OAuth 2.0 JWT Client Authentication and Assertion-Based Authorization Grants (November 2026).
- P. Hosseyni, R. Küsters, T. Würtele, "Audience Injection Attacks: A New Class of Attacks on Web-Based Authorization and Authentication Standards", IACR ePrint 2025/629.
- RFC 8414 §3.3, validating the `issuer` in authorization server metadata.
- RFC 8693, OAuth 2.0 Token Exchange.
- OpenID Connect Core 1.0 §2 and §3.1.3.7, the `aud` and `azp` claims of an ID token.
- RFC 8725 §3.10 (JWT Best Current Practices): use and validate the audience.
