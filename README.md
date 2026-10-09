# lattice-oidc

## Lattice and Authlete: who does what

Authlete is a hosted OAuth 2.0 / OpenID Connect **protocol engine**. Authlete calls its model **semi-hosted**:

- **The operator hosts** the authorization server: its endpoints, sign-in, consent and pages. Lattice is that authorization server.
- **Authlete** handles the protocol work behind those endpoints: parsing and validating requests, issuing and storing tokens, and introspection. Lattice calls it through a REST API.

```mermaid
flowchart LR
    subgraph Clients["API clients"]
        Web["Websites"]
        Mobile["Mobile apps"]
        Devices["Networked devices"]
    end
    subgraph Hosted["Hosted by you"]
        subgraph Lattice["Lattice (authorization server)"]
            Endpoints["OAuth/OIDC endpoints<br/>/api/authorization, /api/token, ..."]
            Identity["Identity and access<br/>sign-in · consent · entitlements"]
            Decision["Authorization decision"]
        end
        APIs["Your APIs / gateway<br/>/data, /function, ..."]
    end
    subgraph Authlete["Authlete (hosted)"]
        Backend["Authorization backend APIs"]
        Tokens[("Token database")]
    end
    Clients -- "OAuth/OIDC requests" --> Endpoints
    Endpoints --> Identity
    Endpoints --> Decision
    Endpoints -- "protocol processing" --> Backend
    Clients -- "API requests with access tokens" --> APIs
    APIs -- "token introspection" --> Backend
    Backend --- Tokens
```

| Lattice decides and keeps | Authlete processes and keeps |
| --- | --- |
| User accounts, passwords (Argon2), passkeys, authenticator apps, LDAP | Request validation for OAuth 2.0, OpenID Connect, PKCE, PAR, CIBA, device flow, FAPI and more |
| Sign-in, sessions, consent (and [remembered consent](#sign-in-and-account-security)), required actions | Authorization codes, access and refresh tokens, and their lifetimes |
| The authorization decision: who may grant what, and which claims are released | ID token signing, discovery metadata, JWKS |
| Pages, audit trail, metrics | Token introspection and revocation |

Authlete never sees a password or any other credential. Lattice authenticates the user, then tells Authlete only the result: the subject, the claims to release and the ACR.

### One authorization, step by step

Each Lattice endpoint forwards the client's request as is, and Authlete's answer (its `action`) tells Lattice what to do next.

| Step | Client calls Lattice | Lattice calls Authlete | Authlete answers |
| --- | --- | --- | --- |
| 1. Authorization request | `GET /api/authorization` | `POST /auth/authorization` with the raw query | `INTERACTION` and a ticket, or an error to return |
| 2. Sign-in and consent | (pages) `POST /api/authorization/decision` | `POST /auth/authorization/issue` with the ticket, subject and claims | `LOCATION`: the redirect carrying the code |
| 3. Token request | `POST /api/token` | `POST /auth/token` | `OK` and the token response to return |
| 4. API access | the client calls your API with the token | your API calls `POST /auth/introspection` (or Lattice's `POST /api/introspection`) | whether the token is valid, its scopes and subject |

The [Tickets](#tickets-a-handle-for-pending-requests) section explains the ticket that links steps 1 and 2.

### Authlete compared with Duende IdentityServer

The two put the boundary in different places.

| | Authlete (with Lattice) | Duende IdentityServer |
| --- | --- | --- |
| Shape | You host the endpoints, in any language. Protocol logic and token storage are a REST service. | The whole token server runs in-process, in your own ASP.NET Core host. |
| Per-request external dependency | Yes: each OAuth/OIDC request calls Authlete. | None: everything is in your infrastructure. |
| Tokens stored | At Authlete. | In your own infrastructure. |
| User credentials | Stay on your side. | Stay on your side. |
| Known for | Financial-grade API (FAPI 1.0 and 2.0) certification and open-banking profiles. | .NET-native identity hosts. |
| Licensing | Authlete's commercial plans. | Editions by features and number of client IDs. |
| Fits | Polyglot or heavily regulated environments that want protocol logic as a service. | Keeping the whole token server inside a .NET system. |

### AI agents, MCP and client ID metadata documents (CIMD)

The Model Context Protocol (MCP) lets AI applications call tools on an MCP server. Its authorization profile uses OAuth 2.1:
- **The authorization server** issues scoped, time-limited access tokens. It decides who gets access and with which permissions.
- **The MCP server** checks the token on each request. It decides whether that request may run.
- **The client is trusted only through its token:** it holds least-privilege access that can be revoked.

**Tokens solve only half the problem.** OAuth assumed that registering a client is a controlled step, done by people. AI agents can appear dynamically, register themselves and ask for broad permissions with no one involved. **CIMD** (OAuth Client ID Metadata Document, an IETF draft) changes how a client is identified:
- **The client ID is a URL:** the client publishes a JSON metadata document at an HTTPS URL, and that URL is its client ID.
- **Fetched on demand:** when a flow starts, the authorization server fetches and validates the document. No registration database is needed.
- **Server-side policy:** the authorization server can add its own validation on top, such as an allowlist of acceptable client hosts.

```mermaid
flowchart LR
    subgraph AI["AI application"]
        Client["MCP client"]
    end
    Metadata["Client metadata document<br/>(on the AI application's website)"]
    subgraph Provider["Service provider"]
        AS["Authorization server<br/>OAuth 2.1, RFC 8414, RFC 8707, RFC 7591, CIMD"]
        MCP["MCP server<br/>OAuth 2.1, RFC 9728"]
        Users[("Users / credentials")]
        Data[("Data / functionality")]
    end
    AuthleteBox["Authlete"]
    Console["Authlete management console:<br/>allowlists, metadata policies"]
    Client -- "authorization / token request, client_id = metadata URL" --> AS
    Client -- "MCP requests with access tokens" --> MCP
    AS --> Users
    MCP --> Data
    AS -- "protocol processing, token management" --> AuthleteBox
    AuthleteBox -- "retrieves" --> Metadata
    Console --> AuthleteBox
```

**Where Lattice stands:**

| Piece | Status in Lattice |
| --- | --- |
| Authorization server metadata (RFC 8414) | Served at `/.well-known/oauth-authorization-server` and `/.well-known/openid-configuration` |
| Dynamic client registration (RFC 7591) | `POST /api/register` |
| Resource indicators (RFC 8707) | Passed to Authlete with the request, as received |
| Protected resource metadata (RFC 9728) | Not Lattice's job: the MCP server (the resource) publishes it |
| CIMD | Not used by Lattice's code yet. Authlete supports it as service settings: client ID metadata documents on or off, an allowlist, whether plain HTTP is permitted, and whether the document is always fetched. Because Lattice forwards the authorization request as is, URL client IDs should work once CIMD is enabled for the Authlete service, but this is untested. Lattice also doesn't yet pass Authlete's per-request `cimdOptions` on its authorization and token calls. |

## Access tokens: what they prove

### Authentication or authorization?

When an API receives `Authorization: Bearer <token>`, two separate things happen:

- **The API authenticates the token, not the person.** It checks the token is genuine: either by verifying its signature, or by asking the authorization server through introspection. It also checks the token is active, unexpired and issued for this API.
- **What the token proves is authorization.** It tells the API which permission the request is using, for example: user 1001 allowed app 42 to `read:notes` until 10:30. The API then decides whether this particular request is allowed.

"The access token authenticates the request" therefore means only that the request is authenticated as a use of that permission. The token doesn't say that the user is present, or that they signed in recently. Nor does it say that the user signed in to this app: that is the ID token's job in OpenID Connect.

| | ID token | Access token |
| --- | --- | --- |
| Question it answers | Who signed in to this app, when and how? | What may the bearer do, at which API, until when? |
| Addressed to | The client app (`aud` = its client ID) | The API (resource server) |
| Used for | Authentication: signing the user in | Authorization: calling APIs |
| Read by the client? | Yes, and validated | No, it's opaque to the client; only the API interprets it |

Treating an access token as proof of sign-in is a classic mistake. Another app the user signed in to could replay a token issued to it as a sign-in. OpenID Connect added the ID token, addressed to one specific client, to keep the two apart.

### Authenticating the "bearer"

With standard OAuth 2.0 bearer tokens (RFC 6750), the API isn't authenticating the sender of the request; it only authenticates the token itself. The security model is that whoever holds the string may use it, like a cinema ticket. The request is authenticated entirely by the presence of a valid token, which is why a stolen bearer token can be successfully replayed by an attacker.

**Sender-constrained tokens** close that gap. The token is bound to a key the client holds, and every request must also prove possession of that key:

| Mechanism | How the client proves possession | Where it's bound |
| --- | --- | --- |
| DPoP (RFC 9449) | A `DPoP` header: a short-lived JWT signed with the client's private key, covering the HTTP method and URL | The token records the key's thumbprint (`cnf.jkt`) |
| Mutual TLS (RFC 8705) | The TLS client certificate presented on the connection | The token records the certificate's thumbprint (`cnf.x5t#S256`) |

A stolen sender-constrained token is useless without the private key. Only then does the token authenticate the sender, as "the client that holds this key". FAPI 2.0 requires one of the two.

**In Lattice:** the token endpoint passes the `DPoP` proof and the TLS client certificate to Authlete, which binds the token to them. The endpoints that accept access tokens pass them again, and Authlete checks that the request matches the binding. Those endpoints are UserInfo, the Open Banking resource APIs and the credential endpoint.

### Opaque or JWT: where the permission is written

Both formats stand for the same permission. They differ in where the API finds it.

- **An opaque token** is a random string that points to a record held by the authorization server (here, Authlete's token database). It contains no user, no scopes and no expiry. The API learns them through introspection (RFC 7662). Its answer always has `active`, and for an active token usually also `sub`, `client_id`, `scope`, `exp` and `aud`.
- **A JWT access token** (RFC 9068) carries those fields itself, signed by the authorization server, so the API verifies the signature and reads them with no network call.

| | Opaque | JWT |
| --- | --- | --- |
| How the API checks it's genuine | Introspection: the server knows it and it's active | Signature verification with the server's public key |
| Where the permission comes from | The introspection response | The token's own claims |
| Revocation | Immediate: the next introspection says `active: false` | It stays valid until it expires, unless the API also asks the server |
| Who can read it | Nobody without the server | Anyone holding it can decode it (signed, not encrypted) |
| Cost per request | A call to the server (usually cached briefly) | Local verification |

Authlete issues opaque access tokens by default, and JWT access tokens when the service is configured with a signing algorithm for them. The ID token is always a JWT, because the client must read it.

### What "grant" means

The word is used in three ways:

- **The permission the user gave**, which is what a token represents: who (`sub`) let which app (`client_id`) do what (`scope`, or `authorization_details` for fine-grained rights) at which API (`aud`) until when (`exp`). In Lattice, the remembered consent (`AppConsentStore`) records this per account and app.
- **An authorization grant, in RFC 6749's sense:** the credential a client exchanges for tokens. The grant types are an authorization code, a refresh token, client credentials, a device code, a CIBA request and others. This is the meaning of `grant_type=authorization_code`.
- **A grant in Grant Management for OAuth 2.0**, a FAPI specification Authlete supports: a long-lived record of a user's permissions for a client, with an ID (`grant_id`) that the client can query, extend or revoke. Lattice serves it at `/api/gm/{grantId}`.

### Consent, grant and access token

The difference is between the human action, the technical record, and the credential issued from that record.

- **Consent** is the user agreeing to delegate access. It happens when a user reads the requested scopes on an authorization screen and clicks "Allow". The word is also used for the stored record of that decision, as with an Open Banking consent or Lattice's `AppConsentStore`.
- **The grant** is the technical permission created as a result of that consent, which the app then holds.
- **An access token** is a short-lived credential issued from the grant, which the app presents to an API.

| | Consent | Grant | Access token |
| --- | --- | --- | --- |
| What it is | The user's decision: "Acme Notes may read my notes" | The permission the app holds: user 1001 → app 42 → `read:notes` | The credential presented to an API to use that permission |
| Held by | The authorization server, as a record of what was approved | The authorization server, on the app's behalf | The app, sent with each API call |
| Lifetime | A moment (approved at 09:12), plus its record | Until revoked or expired by policy | Minutes to an hour |
| How many | One per approval | Usually one per user and app, growing as more is approved | Many: replaced as each expires, usually with a refresh token |
| Scope | What was asked and approved | Everything currently approved | Can be narrower: some scopes, or one API (`aud`) |

As an analogy: consent is signing a power-of-attorney form, the grant is the power of attorney on file, and access tokens are the day passes printed from it.

**A grant can exist without anyone clicking a consent screen:**
- **Client credentials, in machine-to-machine architectures.** No user is involved and nothing is delegated: the app acts for itself. An administrator or system policy pre-authorizes it, by registering which scopes the client may request. RFC 6749 calls the client credentials themselves the authorization grant. No user ever sees a consent screen, but the client can still obtain access tokens. With Authlete, the permission comes from the client's registration rather than from a stored per-user record.
- **Pre-approved apps:** an administrator approved the app for users in advance, or it is a trusted first-party app.
- **Remembered consent:** the user approved the same permissions earlier.

The opposite also holds: if the user clicks Deny, no grant is created.

**Revoking works differently at each level:**
- **One access token:** the grant stays, and the app gets a new token with its refresh token.
- **The grant:** the app's access ends. Its refresh tokens stop working, and opaque access tokens fail introspection at once. JWT access tokens may stay valid until they expire, unless the API checks with the server.
- **The consent record:** the user is simply asked again next time.

**In Lattice:**
- **Consent:** the consent page, logged as `CONSENT_GRANTED` or `CONSENT_DENIED`. `AppConsentStore` remembers the approval so the page can be skipped (`CONSENT_REUSED`).
- **Grant:** held by Authlete and listed on the account page as connected apps. "Remove access" deletes it in Authlete, revoking the app's tokens, and also clears the remembered consent.
- **Access tokens:** issued by Authlete at `/api/token`, and checked by introspection.

## Security fixes compared to the reference server

- JWT bearer and token exchange: the reference never checked the signature on JWT bearer assertions or JWT subject tokens, so a forged JWT got tokens. These are now verified against this server's own Authlete keys or a configured list of trusted issuers; anything else is rejected.
- Pairwise `sub`: computed as a keyed hash per site, so it's opaque and can't be linked across clients. The reference concatenated the sector and the user ID in plain text.
- ACR: an `acr` is only asserted if it's configured as satisfied by password login. The reference echoed back whatever the client asked for.
- Login: passwords are hashed with Argon2 and accounts lock after repeated failures. Response timing doesn't reveal which accounts exist.
- Sessions: a new session ID on every login, server-side invalidation on logout, and pending flows only completable by the browser that started them.
- Browser forms: protected against cross-site form posts (CSRF), with security headers and a CSP set throughout.

### Pairwise sub: a keyed hash instead of plain concatenation

**What pairwise means** (OIDC Core §8.1). A client registered with `subject_type=pairwise` should get a different `sub` for the same user than every other client, so that two sites can't compare notes and work out that they share a user.

The reference built `sub` as `"PAIRWISE-" + sectorIdentifier + "-" + userId`, for example `PAIRWISE-shop.example-1001`. The real user ID sits inside the string, so any two clients can strip the prefix and correlate users. It also leaks the internal user ID.

Lattice computes it in `PairwiseSubjects`:

```text
sub = base64url(HMAC-SHA256(secret, sector + "|" + userId))
```

- Stable: the same user on the same site always gets the same value.
- Unlinkable: different sites get unrelated values.
- Not reversible without the server's secret (`PAIRWISE_SECRET`, falling back to the app secret).

### JWT bearer and token exchange: signatures are now verified

Normally a user logs in at this server through the browser. These two grants let an application get a token for a user without that browser login, by showing proof that someone else has already vouched for the user.

```mermaid
sequenceDiagram
    autonumber
    participant IdP as Some identity provider<br/>(e.g. corporate IdP)
    participant App as Client application
    participant AS as Lattice token endpoint
    participant API as Resource API

    IdP->>App: Signed JWT: "sub = alice, iss = idp.corp, aud = Lattice"
    App->>AS: POST /api/token<br/>grant_type = jwt-bearer<br/>assertion = <that JWT>
    AS->>AS: Is this JWT genuine?
    AS-->>App: access_token for alice
    App->>API: Call API as alice
```

- **JWT bearer (RFC 7523)**: the proof is a JWT signed by someone (the `assertion`).
- **Token exchange (RFC 8693)**: the proof is a token the client already holds (the `subject_token`). It can be an access token, a refresh token, a JWT or an ID token.

```mermaid
flowchart LR
    A[Token request] --> B[Authlete /auth/token]
    B -->|checks client auth,<br/>JWT format, exp, iss present...| C{grant type?}
    C -->|authorization_code,<br/>refresh_token, ...| D[Authlete issues the token itself]
    C -->|jwt-bearer| E[Action JWT_BEARER:<br/>'you decide if this JWT is trustworthy']
    C -->|token-exchange| F[Action TOKEN_EXCHANGE:<br/>'you decide who the subject is']
    E --> G[Our server]
    F --> G
```

Authlete can't verify the signature because it doesn't know which keys to trust. The JWT could be signed by any identity provider in the world, and only the deployment knows which of them it trusts. So the authorization server has to do this check itself.

#### The bug in the reference server

The reference server's `verifySignature()` method was empty, so it trusted whatever the JWT claimed:

```mermaid
sequenceDiagram
    autonumber
    participant Attacker as Attacker<br/>(has any valid client account)
    participant AS as Reference server
    participant Authlete

    Note over Attacker: Writes a JWT by hand:<br/>{"iss":"anything","sub":"1001","aud":"..."}<br/>signed with the attacker's own key (or not signed)
    Attacker->>AS: POST /api/token  grant_type=jwt-bearer  assertion=<forged JWT>
    AS->>Authlete: /auth/token
    Authlete-->>AS: JWT_BEARER (format OK)
    AS->>AS: verifySignature() — empty, nothing checked
    AS->>Authlete: /auth/token/create subject=1001
    Authlete-->>AS: access_token for user 1001
    AS-->>Attacker: 🔓 access_token for user 1001
```

Anyone with any client registration could get tokens for any user, without ever knowing that user's password. That's full account impersonation. Token exchange had the same problem with JWT and ID-token subject tokens.

#### What Lattice checks now

`TokenGrantHandler` hands the JWT to `JwtVerifier`, which only lets it through if every check below passes:

```mermaid
flowchart TD
    S([JWT from assertion / subject_token]) --> A{Signed JWS?<br/>not alg=none,<br/>not encrypted}
    A -- no --> X1[❌ reject]
    A -- yes --> B{Who issued it? 'iss'}
    B -- "this server's own issuer" --> K1[Keys = this server's public keys<br/>from Authlete service JWKS]
    B -- "listed in lattice.trusted-jwt-issuers" --> K2[Keys = that issuer's JWKS URI<br/>fetched + cached]
    B -- anyone else --> X2[❌ reject: issuer not trusted]
    K1 --> C{Signature valid with those keys?<br/>alg in RS/PS/ES/EdDSA allow-list}
    K2 --> C
    C -- no --> X3[❌ reject]
    C -- yes --> D{exp / nbf OK?<br/>not expired, not before}
    D -- no --> X4[❌ reject]
    D -- yes --> E{JWT bearer only:<br/>'aud' names this server?}
    E -- no --> X5[❌ reject]
    E -- yes --> F{Client identifiable?<br/>no anonymous clients}
    F -- no --> X6[❌ reject]
    F -- yes --> OK[✅ subject = 'sub' of the JWT<br/>→ /auth/token/create]
```

All rejections come back to the client as `400 invalid_grant` (or `invalid_request`), and no token is created.

#### What each check stops

| Check                                            | Attack it stops                                                                              |
| ------------------------------------------------ | -------------------------------------------------------------------------------------------- |
| Must be signed, not `alg=none`, not encrypted    | "Unsigned" JWTs that anyone can write                                                        |
| Issuer must be this server or explicitly trusted | An attacker signing with their own key and naming themselves as issuer                       |
| Signature verified with that issuer's real keys  | Forging a JWT that claims to come from a trusted issuer                                      |
| Algorithm allow-list                             | Algorithm-confusion tricks, such as switching to HMAC and using the public key as the secret |
| `exp` / `nbf`                                    | Reusing an old, leaked JWT indefinitely                                                      |
| `aud` must be this server (JWT bearer)           | Replay: a genuine JWT that the IdP issued for another service, reused here                   |
| Client must be identifiable                      | Anonymous callers using the grant at all                                                     |

#### Legitimate and forged assertions side by side

```mermaid
sequenceDiagram
    autonumber
    participant C as Client
    participant L as Lattice (TokenGrantHandler + JwtVerifier)
    participant K as Trusted issuer's JWKS
    participant A as Authlete

    rect rgb(230, 245, 230)
    Note over C,A: Legitimate: JWT from a trusted IdP, aud = Lattice
    C->>L: assertion signed by idp.corp
    L->>K: fetch idp.corp public keys (cached)
    K-->>L: keys
    L->>L: signature ✓ exp ✓ aud ✓ client ✓
    L->>A: /auth/token/create subject=alice
    A-->>L: token
    L-->>C: 200 access_token
    end

    rect rgb(250, 230, 230)
    Note over C,A: Forged: iss = evil.example, signed with attacker's key
    C->>L: assertion from evil.example
    L->>L: issuer not in trusted list
    L-->>C: 400 invalid_grant "issuer not trusted"
    Note over L,A: Authlete /auth/token/create is never called
    end
```

### Login: Argon2 hashing, lockout, and no account enumeration

- Argon2 hashing, a memory-hard algorithm that makes offline cracking expensive. Demo passwords are hashed when the store loads; nothing is stored in plain text.
- Lockout: failed sign-ins are counted over `lattice.login.lockout` (15 minutes) in three ways, and reaching any limit refuses further attempts, even with the correct password, until the window ends. The user sees "Too many failed attempts".
  - for one account from one IP address: `lattice.login.max-failures` (default 5);
  - for one account from any IP address: `max-failures-per-account` (20);
  - from one IP address for any accounts: `max-failures-per-ip` (50), against password spraying.

  Counting per account and IP first means someone guessing from elsewhere can't lock the real user out with a handful of attempts.

### Sessions: rotation, real logout, and pending flows tied to one browser

**Session ID rotation** (`UserSessions.login`). Every successful login creates a brand-new session ID (`session_id` in the cookie). This prevents session fixation, where an attacker plants a known session ID in the victim's browser before they log in and then rides on it afterwards.

**Server-side invalidation.** Play's session cookie is signed, but anyone holding a copy can replay it. So the cookie only carries the session ID, and a session counts as valid only while that session ID is registered on the server. Logout removes it there, so a stolen or replayed copy of the old cookie stops working. A test checks this. The session ID is also what back-channel logout and native SSO key on, and it is sent to clients as the `sid` claim of ID tokens and logout tokens.

**Pending flows bound to the browser** (`Interactions`). Each browser gets a stable random ID (`browser_id`) in its cookie. Pending consent, device-approval and federation-login state is stored server-side under its ticket or code and tagged with that `browser_id`. Completing a flow requires the same `browser_id`. That stops an attacker who learns or guesses a ticket from completing the consent or device approval from their own browser, and it stops cross-site requests from finishing someone else's flow. CSRF tokens on the forms add a second layer.

**Single use.** The ticket is removed when it's used, so a replayed decision fails. That's tested too.

**Idle timeout.** A session ends after `lattice.session.idle-timeout` (default 30 minutes) without activity, and in any case after `lattice.session.max-lifespan` (10 hours). An app using the session through native SSO counts as activity.

## Project structure

```text
com.lattice.oidc
├── controllers/   thin Play controllers, one per spec area; routes point here
│                  BaseController, Authorization, Token, UserInfo, Introspection,
│                  Revocation, Par, ClientRegistration, GrantManagement, Discovery, Ciba,
│                  Device, Credential, CredentialOffer, Federation (OpenID Federation 1.0),
│                  IdentityBroker, Obb, Logout, Health, Test
├── handlers/      protocol logic: AuthorizationHandler, TokenGrantHandler (exchange/JWT bearer),
│                  NativeSsoHandler, CibaHandler, DeviceHandler, CredentialOrderHandler,
│                  ObbDcrHandler, ObbTokenHandler, LogoutHandler,
│                  IdentityProvider, IdentityProviders (identity brokering)
├── models/        AuthorizationPage, AuthorizationInteraction, Consent, User, IdentityProviderConfig, ...
├── security/      LoginService, UserSessions, Interactions, JwtVerifier, PairwiseSubjects,
│                  ObbCertValidator, AuditService
├── stores/        UserStore, InMemoryUserStore, ConsentStore
├── client/        Authlete Play WS client, ServerMetadata
├── filters/       RequestIdFilter, HstsFilter, AccessLogFilter
├── common/        Requests, Responses, Jsons, WebException, ErrorHandler, Redaction, LatticeConfig
└── modules/       AuthleteModule
```

## Design and screens

Designs for all 15 end-user and operator screens (sign-in, consent, device flow, CIBA, logout, account, wallets, open banking and the operator console) are in [docs/screens](docs/screens/README.md), with the design language, the flow each screen belongs to, and whether it is built yet.

## Running the server in production

```sh
sbt --client stage
APPLICATION_SECRET=$(openssl rand -hex 32) \
AUTHLETE_SERVICE_APIKEY=<id> AUTHLETE_SERVICE_ACCESSTOKEN=<token> \
LATTICE_STORAGE=postgres DATABASE_URL=jdbc:postgresql://db:5432/lattice \
DATABASE_USERNAME=lattice DATABASE_PASSWORD=<password> \
target/universal/stage/bin/lattice-oidc -Dhttp.port=9000
```

### Storage

`lattice.storage` (`LATTICE_STORAGE`) chooses where state is kept:

| Value | Where | Use for |
| --- | --- | --- |
| `memory` (default) | In this server's memory; lost on restart | Development and tests |
| `postgres` | PostgreSQL, shared by every server and kept across restarts | Production, one server or several |

With `postgres`:
- **Kept durably:** accounts, passkeys, identity links and Open Banking consents.
- **Shared between servers:** login sessions, pending sign-ins, password reset links, CIBA requests, native SSO device secrets, sign-in alerts and the rate-limit counters. Any server can continue a flow another one started, so no sticky sessions are needed.
- **Schema:** created and migrated at startup by Flyway (`conf/db/migration`). A wrong URL or password stops the server at startup, not at the first sign-in.
- **Cleanup:** every server deletes expired rows every `lattice.postgres.cleanup-interval` (1 minute).
- **Same secret everywhere:** every server must use the same `APPLICATION_SECRET`, because it signs the session cookie.

| Setting | Environment variable | Default |
| --- | --- | --- |
| `lattice.postgres.url` | `DATABASE_URL` | `jdbc:postgresql://localhost:5432/lattice` |
| `lattice.postgres.username` | `DATABASE_USERNAME` | `lattice` |
| `lattice.postgres.password` | `DATABASE_PASSWORD` | empty |
| `lattice.postgres.maximum-pool-size` | `DATABASE_POOL_SIZE` | 10 |

With `lattice.demo-users` on, the demo accounts are added only to an empty `users` table, so a real database is never changed.

### Short-lived state and the read cache

Two more settings decide where the fast-moving data goes. Each is independent of `lattice.storage`:

| Setting | Values | What it controls |
| --- | --- | --- |
| `lattice.short-lived-state` (`LATTICE_SHORT_LIVED_STATE`) | `storage` (default), `redis` | Single-use state: sign-in state and nonce, consent tickets, reset links, CIBA approvals, device secrets, sign-in alerts. Also the rate-limit counters. This data needs no durability, so Redis suits it. |
| `lattice.cache.type` (`LATTICE_CACHE`) | `none` (default), `local`, `redis` | A read cache in front of the two lookups made on every signed-in request: the user by subject and the session by id. |

How the cache stays correct:
- **Changes invalidate it everywhere.** A sign-out, a password change or a removed passkey invalidates the cached copy on every server at once. With `local`, each server keeps its own copy and changes are announced through PostgreSQL `LISTEN`/`NOTIFY`. With `redis`, there is one shared copy.
- **`lattice.cache.ttl` (30 seconds)** bounds the rare race where a copy is read just before a change and stored just after it.
- **Never cached:** single-use state and counters. They rely on one atomic step in their store; a cached copy would allow reuse or under-counting.
- **Password hashes are cached** along with the user, so secure Redis as you would the database.

| Redis setting | Environment variable | Default |
| --- | --- | --- |
| `lattice.redis.url` | `REDIS_URL` | `redis://localhost:6379` (use `rediss://` for TLS, `redis://:password@host:6379` for a password) |
| `lattice.redis.key-prefix` | `REDIS_KEY_PREFIX` | `lattice:` (lets several deployments share one Redis) |

PostgreSQL and Redis are both checked at startup, so a wrong address stops the server at startup instead of the first sign-in.

### Sign-in and account security

**Keep me signed in** (`lattice.session.remember-me`). Password sign-in offers a checkbox. Remembered sessions last up to 30 days and end after 7 days without activity; others keep the 30-minute idle limit and 10-hour lifetime. The session cookie itself lives 30 days and the server enforces each session's limits, so closing the browser doesn't end an unremembered session that's used again within 30 minutes.

**Two-step verification** (`lattice.second-factor`). Users can set up an authenticator app (TOTP, RFC 6238) from their account page. After that, password sign-in also asks for a 6-digit code.
- **Recovery codes:** 10 are issued when the app is set up and shown once. Each can replace a code exactly once.
- **Stored safely:** app secrets are encrypted (AES-GCM) and recovery codes stored as keyed hashes.
- **No reuse:** a code is accepted once.
- **Wrong codes:** count towards `lattice.login.max-failures`.
- **ACR:** signing in with a code asserts the ACR `mfa`.
- **`required = true`:** every account must have an authenticator app or a passkey.
- **Exempt:** passkey sign-in, since a passkey is already two factors.
- **The password grant** refuses accounts with an app, because it can't ask for a code.

**Rotating the two-step key** (`encryption-key`, or the application secret when it's empty). Every stored secret and recovery-code hash carries the id of its key.
1. Set the new `encryption-key`, and list the old one in `previous-encryption-keys` (`SECOND_FACTOR_PREVIOUS_ENCRYPTION_KEYS`, comma-separated).
2. Secrets under the old key are still read. Each is re-encrypted under the new key when it's next used, and at startup a background pass re-encrypts the rest.
3. Recovery codes can't be re-hashed, because only their hashes are kept. Codes made under the old key keep working until the account makes new ones.
4. The console's **Two-step verification** panel counts what is still under a previous key. When both counts are zero, remove the old key.

**Remembered consent.** Approving an app on the consent page records which scopes and claims were approved, for that account and app, in the same storage as everything else. The approval then applies in every browser and on every server.
- **Not asked again:** a later request that asks for nothing more is issued straight away, after signing in if needed, and logged as `CONSENT_REUSED`. A request that asks for more shows the page again.
- **Always asked:** when the app sends `prompt=consent`, for Open Banking consents, and for identity-verification (`verified_claims`) or transaction claims, which are approved each time.
- **Silent sign-in** (`prompt=none`) is issued only for what was approved; anything else fails with `consent_required`.
- **Forgotten:** when the user removes the app on their account page, or an operator deletes the app.

**Required actions** (`lattice.required-actions`). Steps a user must complete before using apps or their account: verify their email (a link is emailed), accept a new version of the terms, choose a new password, or set up an authenticator app or a passkey. Each is pending while its condition holds, so it clears itself once met. They're enforced everywhere a signed-in user goes:
- **Consent pages** wait for them.
- **Account, approval, console, device and credential-offer pages** redirect to them.
- **Silent sign-in** (`prompt=none`) fails with `interaction_required`.
- **The password grant** refuses the account.

Enable them for everyone with `verify-email` and `terms-version`, or for one account by listing actions in its `requiredActions` attribute.

**LDAP and Active Directory** (`lattice.ldap`). Read-only user federation, like Keycloak's:
- **Sign-in:** a sign-in that isn't a local account is looked up in the directory, and the password is checked with an LDAP bind.
- **Copied locally:** the user is then copied into Lattice's store, keyed by the entry's stable id (`entryUUID`, or `objectGUID` on Active Directory), and refreshed at every sign-in. Passkeys, authenticator apps and sessions stay in Lattice.
- **Passwords:** password change and reset are left to the directory.
- **Outages:** a directory outage shows "temporarily unavailable" and doesn't count towards the lockout.
- **Startup check:** the connection is checked at startup.
- **TLS:** use `ldaps://` or `start-tls`; without either, a warning is logged, because passwords would be sent in clear. The directory's certificate must chain to a CA the JVM trusts, or to one in `trust-store`, a PEM file or a PKCS#12/JKS store with `trust-store-password`. It must also name the host in `url`.
- **Console:** the **LDAP directory** panel shows whether the directory answers, the connection pool, sign-ins checked against it, and the last error.

### Audit trail, webhooks and metrics

**Sign-in events say which step happened.**
- `LOGIN_SUCCEEDED` records `method`: `password`, `password + totp`, `password + recovery_code` or `passkey`.
- With an authenticator app, the right password is `SECOND_FACTOR_REQUIRED` (`factor: totp`). It isn't a sign-in until the code is accepted.
- A wrong code is `SECOND_FACTOR_FAILED`, with `factor` set to `totp` or `recovery_code`. `LOGIN_FAILED` is kept for wrong passwords and passkeys.
- A signed-in user re-entering their password before a sensitive change is `PASSWORD_CONFIRMED`.
- `SECOND_FACTOR_ADDED` and `SECOND_FACTOR_REMOVED` name the factor.

The console's event tables show these fields in a **Details** column.

**Stored audit events** (`lattice.audit`). Every security event (sign-ins, consents, sign-outs, password and second-factor changes, client changes, ...) is also stored. With PostgreSQL storage they're kept for `retention` (90 days); in memory, the latest 10,000 are kept. The operator console's **Audit log** page lists them, newest first, filterable by event and account.

**Webhooks** (`lattice.webhooks`). Events can be sent to endpoints such as a SIEM, signed the Standard Webhooks way: `webhook-id`, `webhook-timestamp`, and `webhook-signature: v1,<HMAC-SHA256 of id.timestamp.body>`.
- **Configuration:** each endpoint has a secret and an optional list of events. One endpoint can also come from `WEBHOOK_URL`, `WEBHOOK_SECRET` and `WEBHOOK_EVENTS`.
- **Retries:** a failed delivery is retried after 5 seconds, 30 seconds and 2 minutes. Retries are kept in memory, so a restart drops any that are waiting.
- **Console:** the **Webhooks** panel shows, per endpoint on that server, deliveries, waiting retries, deliveries given up and the last error.

**Metrics** (`lattice.metrics`, off by default). `GET /metrics` serves Prometheus metrics:
- **Requests:** HTTP requests by route and status; audit events by type.
- **Authlete:** API calls by operation, outcome and latency; tasks queued and running on its thread pool, and the pool size.
- **Storage:** active sessions; short-lived entries by namespace (pending sign-ins, device codes, reset links); read-cache hits and misses, size and evictions; the PostgreSQL pool; rows deleted by each cleanup run; reconnects of the cache-invalidation listener.
- **Redis:** every command by name, outcome and latency; the connection pool.
- **Outbound:** webhook deliveries per endpoint (delivered, retry, failed) and retries waiting; LDAP searches and binds by outcome, and its pool; sign-ins through each upstream identity provider; emails sent or failed.
- **Two-step:** accounts with an authenticator app, and what is still under a previous encryption key.
- **JVM and process:** memory, heap pressure, garbage collection, threads, CPU, open files, uptime, JVM version, and log events by level.

Figures read from storage are refreshed at most every 30 seconds, however often Prometheus scrapes. Webhook endpoints are tagged by position and host, never by path, which may hold a secret.

Tags never contain user data. Set `METRICS_TOKEN` to require `Authorization: Bearer <token>`, and keep the endpoint off the public internet.

## Tickets: a handle for pending requests

A ticket is Authlete's handle for a request it is in the middle of processing. When Authlete can't finish a request on its own (for example, it needs the user to log in and consent), it remembers the parsed request on its side and gives Lattice an opaque string, the ticket. Lattice later sends that ticket back to finish the request (issue) or reject it (fail).

```mermaid
sequenceDiagram
    autonumber
    participant B as Browser
    participant L as Lattice
    participant A as Authlete

    B->>L: GET /api/authorization?client_id=...&scope=...
    L->>A: /auth/authorization (raw parameters)
    A-->>L: action=INTERACTION, ticket=T, client, scopes, claims...
    Note over A: Authlete keeps the validated request under T
    L-->>B: consent page (hidden field ticket=T)
    B->>L: POST /api/authorization/decision ticket=T, login, Authorize
    L->>A: /auth/authorization/issue ticket=T, subject=1001, claims...
    A-->>L: action=LOCATION, redirect with code
    L-->>B: 302 → client redirect_uri?code=...
```

## Single sign-on

Once a browser has a login session at Lattice, other applications can reuse it without asking for the password again.

```mermaid
sequenceDiagram
    autonumber
    participant U as Browser
    participant A as App A
    participant B as App B
    participant L as Lattice

    U->>A: open App A
    A-->>U: redirect to Lattice /api/authorization
    U->>L: log in (password) → session ID created
    L-->>A: code → tokens
    U->>B: later, open App B
    B-->>U: redirect to Lattice /api/authorization
    U->>L: session cookie already valid → no password asked
    L-->>B: code → tokens
    Note over U,L: That's SSO: one login at Lattice, many apps
```

## Identity brokering

Identity brokering lets users sign in to Lattice with an existing account at an external identity provider such as Okta, Azure AD or Google. Lattice delegates authentication to that provider, verifies the result, and maps the external identity to a local account (for example `alice@okta`) with its own Lattice session. Keycloak calls this feature Identity Brokering; it is also known as social login or upstream identity providers.

### `IdentityProvider`: one upstream provider

Code: `handlers/IdentityProvider.java` (Keycloak: `OIDCIdentityProvider`).

Each instance is the relying-party client for a single OpenID Provider (one entry in the identity providers file, for example `"okta"`). It does the actual protocol work with that provider:

- **Discovery**: fetches and caches the provider's `/.well-known/openid-configuration` and checks that `issuer` matches.
- `authenticationRequest(state, verifier, nonce)`: builds the redirect URL to the provider's authorization endpoint, using the code flow with PKCE, `state` and `nonce`.
- `complete(callbackUrl, state, verifier, nonce)`:
  1. Parses the callback and checks `state`.
  2. Exchanges the code at the provider's token endpoint.
  3. Validates the ID token (signature from the provider's JWKS, issuer, audience, nonce).
  4. Calls UserInfo and checks that its `sub` matches the ID token's.

### `IdentityProviders`: the registry

Code: `handlers/IdentityProviders.java`. A `@Singleton` that holds every configured provider:

- At startup: reads the JSON file named by `lattice.identity-providers.file` (`IDENTITY_PROVIDERS_FILE`; `FEDERATIONS_FILE` is still accepted), skips incomplete entries with a warning, and creates one `IdentityProvider` per valid entry. The file has a top-level `identityProviders` array; entries use the format of java-oauth-server's `federations.json`, and its top-level `federations` key is still accepted.
- A ready-made example with Okta, Microsoft, Google, Keycloak and PingFederate entries is in `conf/identity-providers.example.json`. Copy it, fill in your values, and point `IDENTITY_PROVIDERS_FILE` at it. Each `redirectUri` must be `<base URL>/api/federation/callback/<id>` and registered at the provider.
- `get(id)`: looks up the `IdentityProvider` for an ID such as "okta". `IdentityBrokerController` uses it in `/api/federation/initiation/:id` and `/api/federation/callback/:id`.
- `links()`: returns (id, name) pairs so the consent page can show "Or sign in with: Okta, …".

```mermaid
flowchart LR
    F[identity providers file] -->|startup| R[IdentityProviders<br/>registry]
    R -->|"get('okta')"| O[IdentityProvider okta]
    R -->|"get('azure')"| A[IdentityProvider azure]
    R -->|"links()"| P[Consent page:<br/>'Sign in with Okta / Azure']
    C[IdentityBrokerController] -->|initiation / callback| R
    O <-->|discovery, code flow,<br/>ID token, UserInfo| X[(Okta)]
```

### The flow at a glance

Lattice is the client here, and an external provider (Okta, Azure AD, Google…) authenticates the user.

```mermaid
sequenceDiagram
    autonumber
    participant U as User's browser
    participant L as Lattice (acting as RP)
    participant O as Okta (external OP)

    U->>L: Consent page → clicks "Sign in with Okta"
    L-->>U: redirect /api/federation/initiation/okta → Okta authorize
    U->>O: logs in at Okta
    O-->>U: redirect back with code
    U->>L: /api/federation/callback/okta?code=...
    L->>O: exchange code, validate ID token, call UserInfo
    L->>L: create/update local user "sub@okta", log them in
    L-->>U: consent page again, now logged in
```

### The flow in detail

```mermaid
sequenceDiagram
    participant App as Client app
    participant B as Browser
    participant L as Lattice
    participant A as Authlete
    participant O as Okta (upstream)

    App->>B: redirect to /api/authorization
    B->>L: GET /api/authorization
    L->>A: /auth/authorization
    A-->>L: INTERACTION + ticket
    L-->>B: consent page with "Continue with Okta"<br/>(ticket stored, bound to browser_id)
    B->>L: GET /api/federation/initiation/okta?ticket=…
    L->>L: new state, PKCE verifier, nonce<br/>stored under state + browser_id
    L-->>B: 302 to Okta /authorize
    B->>O: user logs in at Okta
    O-->>B: 302 to /api/federation/callback/okta?code&state
    B->>L: callback
    L->>O: token request (code + PKCE verifier)
    O-->>L: access token + ID token
    L->>L: verify ID token (signature, iss, aud, exp, nonce)
    L->>O: UserInfo
    L->>L: subject must match the ID token<br/>save user "sub@okta", new session ID
    L-->>B: consent page, "Signed in as Alice"
    B->>L: Allow
    L->>A: /auth/authorization/issue (subject = sub@okta)
    L-->>B: 302 to client with code
```

### Summary

- **Question it answers**: "Who is this user?" Another provider vouches for them.
- **Direction**: Lattice is the client of Okta. It has a client_id and secret at Okta.
- **Code**: `IdentityProvider`, `IdentityProviders`, and `IdentityBrokerController` (`initiation`, `callback`).
- **Configured in**: the identity providers file (`lattice.identity-providers.file`).
- **Spec**: plain OpenID Connect, with Lattice on the client side.

## OpenID Federation 1.0

OpenID Federation 1.0 is a trust framework that lets client applications and providers trust each other through a shared authority, so clients don't need to be registered manually. It is what `/.well-known/openid-federation` and `/api/federation/register` implement. Lattice is the provider here: instead of every client being registered in advance, a shared trust anchor (for example a national open-banking directory) vouches for both the provider and its clients, and trust is checked by following a chain of signed statements.

### Why it exists

In plain OpenID Connect, trust is set up one pair at a time. Before a relying party (RP, the client app) can use an OpenID Provider (OP), the two have to know each other:

| Approach                               | How the RP gets known to the OP                  | What's still missing                                                                                                           |
| -------------------------------------- | ------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------ |
| Static registration                    | An admin registers the client by hand at each OP | Doesn't scale: 1,000 RPs × 50 OPs means 50,000 manual registrations                                                            |
| Dynamic Client Registration (RFC 7591) | The RP registers itself through an API           | It solves the mechanics, not trust: the OP still can't tell whether the client is a real, approved organisation or an attacker |

Large ecosystems hit this immediately: national eID schemes (Italy's SPID/CIE run on OpenID Federation), university networks, open banking, health networks and EU digital identity wallets. Thousands of parties that have never met still need to trust each other automatically.

**OpenID Federation's answer is to make trust hierarchical, the way TLS certificates work.** A single authority (the Trust Anchor) vouches for a set of intermediates, which in turn vouch for the relying parties and providers. The relying party can verify the chain of trust up to the anchor, and the provider can do the same. That way, a relying party can be registered automatically without any prior relationship with the provider.

Trust Anchors vouch for intermediates, intermediates vouch for the actual OPs and RPs, and each of these "vouches" is a signed JWT. Two parties that have never met can each follow a chain of these JWTs up to a Trust Anchor they both trust. If both chains reach it, they trust each other, with no prior registration.

### Where it's used

Real ecosystems hit that scale whenever many relying parties each have to accept many identity providers, usually because the user picks their own provider from a list. Every RP then needs a working relationship with every OP. Here are the real-world cases.

#### National digital identity: the best-known case

Italy's SPID is the textbook example, and it's one of the first large deployments of OpenID Federation.

- Citizens get their digital identity from one of about a dozen accredited private identity providers (Poste, Aruba, InfoCert and others).
- Thousands of relying parties (municipalities, ministries, tax and health services, universities, plus private companies) all show a "Sign in with SPID" button listing every provider.
- That's thousands × about a dozen pairwise relationships, all of which must carry correct keys and metadata, stay current through key rotation, and be cut off immediately when a party is suspended.

The real burden isn't the first registration but keeping all those pairs correct afterwards. That's the problem a Trust Anchor solves: a service joins once, and every provider trusts it automatically.

#### Research and education

Universities worldwide run identity providers, and services such as journal publishers, research tools, eduroam and cloud computing grants want to accept users from any university. National federations (InCommon, the UK federation, DFN and others) and eduGAIN, which links them, are the trust frameworks that make this work. They mostly run on SAML metadata today, and OpenID Federation 1.0 is designed partly as the OIDC counterpart of that model.

#### Open banking and open finance

Every bank (acting as the OP for its customers) must accept every licensed third-party provider (budgeting apps, payment initiators), and every provider wants to connect to every bank.

Brazil's Open Finance has hundreds of participating institutions, any of which may need to connect to any other.

This is already in Lattice. `ObbDcrHandler` handles the open banking solution to this exact problem. A central directory signs a software statement for every licensed provider, and banks trust the directory instead of each provider. That's a one-level version of federation: the directory plays the Trust Anchor and the software statement plays the Subordinate Statement. OpenID Federation generalises it with intermediates, metadata policies and trust marks.

#### Digital identity wallets (EU and others)

- Millions of wallets, many credential issuers (governments, universities, banks, employers) and very many verifiers (any shop, rental company or website checking an ID or diploma).
- A verifier needs to know whether an issuer is legitimate, and a wallet needs to know whether the verifier asking for your passport data is allowed to ask.
- This is the newest and biggest use case. OpenID Federation is one of the trust frameworks being used or considered with OID4VCI and OID4VP.

#### Health care

Hospitals, labs, insurers and patient apps across a region or country need to trust each other's systems for patient login and data exchange. Many independent organisations, each acting as both provider and consumer, again produce the many-to-many shape.

#### What decides whether you need it

The deciding factor isn't raw numbers. It's whether there's an ecosystem with a governing authority (a government, a banking regulator, a research network) that sets the rules and decides who's in. That authority becomes the Trust Anchor. Without one, there's nobody to anchor the trust to.

### Entities and roles

Every participant is an entity, identified by an Entity ID, which is an HTTPS URL (for example `https://op.lattice.example`).

```mermaid
flowchart TD
    TA[Trust Anchor<br/>e.g. national federation operator]
    IA1[Intermediate<br/>e.g. Ministry of Health]
    IA2[Intermediate<br/>e.g. Universities consortium]
    OP[Leaf: OpenID Provider<br/>e.g. Lattice]
    RP1[Leaf: Relying Party<br/>hospital portal]
    RP2[Leaf: Relying Party<br/>university app]
    TA --> IA1
    TA --> IA2
    IA1 --> OP
    IA1 --> RP1
    IA2 --> RP2
```

| Role                   | What it does                                                                                               |
| ---------------------- | ---------------------------------------------------------------------------------------------------------- |
| Trust Anchor (TA)      | The root of trust. Its keys are configured out-of-band, the way root CA certificates ship in a browser     |
| Intermediate Authority | Vouches for entities below it. Lets an ecosystem delegate, for example "the Ministry approves health apps" |
| Leaf entity            | Does the real work: an OP, an RP, a credential issuer, a wallet provider                                   |
| Trust Mark Issuer      | Issues signed badges such as "certified for the health sector" or "passed the security audit"              |

Every participant in the federation is an entity: Trust Anchors, Intermediates, leaves, Trust Mark Issuers and resolvers. The roles differ by where an entity sits in the tree:

- **A leaf** is an entity with no subordinates. It does the actual OIDC work.
- **A Trust Anchor** is an entity with no superior. Its Entity Configuration has no `authority_hints`, and its keys are trusted because you configured them, not because anyone vouched for it.
- **An Intermediate** has both: a superior above it and subordinates below it.

1. **The Trust Anchor publishes a self-signed Entity Configuration, like everyone else.** That's how others discover its fetch endpoint and current keys. But you don't trust it because of that file: you check that the keys in it match the ones you were configured with.
2. **Roles are relative to the chain.** An entity that is the Trust Anchor in one federation can be an Intermediate in another, for example a national federation that is itself a member of an EU-wide one. A trust chain always ends at whichever Trust Anchor you chose to trust.
3. **One entity can play several protocol roles at once.** Lattice is a single leaf entity that is both an `openid_provider` and an `openid_credential_issuer`. That's why `FederationController.java` asks Authlete for an Entity Configuration with both entity types.

### Entity Configuration: what an entity says about itself

Every entity publishes a self-signed JWT at `<entity-id>/.well-known/openid-federation`. Its media type is `application/entity-statement+jwt`, and its payload looks like this:

```json
{
  "iss": "https://op.lattice.example",
  "sub": "https://op.lattice.example",
  "iat": 1760000000,
  "exp": 1760086400,
  "jwks": { "keys": [ { "kty": "EC", "kid": "fed-1", ... } ] },
  "authority_hints": [ "https://health.gov.example" ],
  "metadata": {
    "federation_entity": { "organization_name": "Lattice" },
    "openid_provider": {
      "issuer": "https://op.lattice.example",
      "authorization_endpoint": "https://op.lattice.example/api/authorization",
      "token_endpoint": "https://op.lattice.example/api/token",
      "client_registration_types_supported": ["automatic", "explicit"],
      "federation_registration_endpoint": "https://op.lattice.example/api/federation/register"
    },
    "openid_credential_issuer": { ... }
  },
  "trust_marks": [ { "id": "https://health.gov.example/certified", "trust_mark": "eyJ..." } ]
}
```

- `iss` = `sub`: marks it as self-signed: the entity is talking about itself.
- `jwks`: holds the entity's federation keys. These sign federation statements only. They are separate from its normal OIDC signing keys, which go in the metadata as usual.
- `authority_hints`: says "my superiors are here", so others know where to look next.
- `metadata`: holds the normal OIDC/OAuth metadata, grouped by entity type, because one entity can play several roles. Ours is both an OP and a credential issuer.

On its own this proves nothing, since anyone can sign a statement about themselves. A superior has to vouch for it.

### Subordinate Statement: what a superior says about you

A superior publishes a Subordinate Statement about each entity it vouches for. It's served from the superior's fetch endpoint (`federation_fetch_endpoint?sub=<entity-id>`):

```json
{
  "iss": "https://health.gov.example",
  "sub": "https://op.lattice.example",
  "exp": 1760086400,
  "jwks": { "keys": [ { "kid": "fed-1", ... } ] },
  "metadata_policy": {
    "openid_provider": {
      "id_token_signing_alg_values_supported": { "subset_of": ["ES256", "PS256"] },
      "token_endpoint_auth_methods_supported": { "subset_of": ["private_key_jwt", "tls_client_auth"] }
    }
  },
  "constraints": { "max_path_length": 1 }
}
```

- It is signed by the superior's key (`iss` ≠ `sub`).
- Its `jwks` pins the subordinate's federation keys: "the real Lattice signs with key `fed-1`". This is what stops an impostor from publishing a fake Entity Configuration, because the impostor's key won't match the one the superior pinned.
- `metadata_policy` lets the superior restrict or modify the subordinate's metadata.
- `constraints` limits what can happen further down the tree, such as path length or allowed entity types.

### Trust chains

Each entity publishes its own Entity Configuration at `/.well-known/openid-federation`. Its superior publishes a Subordinate Statement about it at its fetch endpoint. A trust chain links the two: each Subordinate Statement names its subject (`sub`) and that subject's keys, so it binds the statement below it. The chain starts with the leaf's Entity Configuration and ends with the Trust Anchor's:

```text
.----------------.  .---------------------------.         .---------------------------.
| Role           |  | .well-known/              |         | Trust Chain               |
|                |  | openid-federation         |         |                           |
.----------------.  .---------------------------.         .---------------------------.
| .------------. |  | .-----------------------. |         | .-----------------------. |
| |            | |  | | Entity Configuration  | |         | | Entity Configuration  | |
| |Trust Anchor+-+--+->                       +-+---------+->                       | |
| |            | |  | | Federation Entity Keys| |         | | Federation Entity Keys| |
| '-----.------' |  | | Metadata              | |         | | Metadata              | |
|       |        |  | | Trust Mark Issuers    | |         | | Trust Mark Issuers    | |
|       |        |  | |                       | |         | |                       | |
|       |        |  | '-----------------------' |         | '-----------------------' |
|       |        |  |                           |         |                           |
|       |        |  |                           |Fetch    | .-----------------------. |
|       |        |  |                           |Endpoint | | Subordinate Statement | |
|       +--------+--+---------------------------+---------+->                       | |
|                |  |                           |         | | Federation Entity Keys| |
|                |  |                           |         | | Metadata Policy       | |
|                |  |                           |         | | Metadata              | |
|                |  |                           |         | | Constraints           | |
|                |  |                           |         | |                       | |
|                |  |                           |         | '-----------.-----------' |
| .------------. |  | .-----------------------. |         |             |             |
| |            | |  | | Entity Configuration  | |         |             |sub and key  |
| |Intermediate+-+--+->                       | |         |             | binding     |
| |            | |  | | Federation Entity Keys| |         | .-----------v-----------. |
| '------.-----' |  | | Metadata              | |         | | Subordinate Statement | |
|        |       |  | | Trust Marks           | |         | |                       | |
|        |       |  | |                       | |         | | Federation Entity Keys| |
|        |       |  | '-----------------------' |Fetch    | | Metadata Policy       | |
|        |       |  |                           |Endpoint | | Metadata              | |
|        +-------+--+---------------------------+---------+->                       | |
|                |  |                           |         | '-----------.-----------' |
|                |  |                           |         |             |sub and key  |
|                |  |                           |         |             | binding     |
| .------------. |  | .-----------------------. |         | .-----------v-----------. |
| |            | |  | | Entity Configuration  | |         | | Entity Configuration  | |
| | Leaf       +-+--+->                       +-+---------+->                       | |
| |            | |  | | Federation Entity Keys| |         | | Federation Entity Keys| |
| '------------' |  | | Metadata              | |         | | Metadata              | |
|                |  | | Trust Marks           | |         | | Trust Marks           | |
|                |  | |                       | |         | |                       | |
|                |  | '-----------------------' |         | '-----------------------' |
'----------------'  '---------------------------'         '---------------------------'
```

Read the right-hand column bottom-up, as a verifier does:
- **Leaf's Entity Configuration:** self-signed, carrying the leaf's own keys, metadata and Trust Marks.
- **Intermediate's Subordinate Statement about the leaf:** vouches for the leaf's keys and applies the intermediate's metadata policy.
- **Trust Anchor's Subordinate Statement about the intermediate:** the same, one level up, plus constraints such as how deep the chain may go.
- **Trust Anchor's Entity Configuration:** its keys must match the ones the verifier already trusts.

#### Building the chain

Suppose a hospital portal (RP) wants to trust Lattice (OP), and the RP is configured to trust `https://federation.gov.example` as its Trust Anchor.

```mermaid
sequenceDiagram
    participant RP as Hospital portal (RP)
    participant OP as Lattice (OP)
    participant IA as health.gov (Intermediate)
    participant TA as federation.gov (Trust Anchor)

    RP->>OP: GET /.well-known/openid-federation
    OP-->>RP: Entity Configuration (self-signed)<br/>authority_hints: health.gov
    RP->>IA: GET /.well-known/openid-federation
    IA-->>RP: IA's Entity Configuration<br/>authority_hints: federation.gov
    RP->>IA: GET /fetch?sub=https://op.lattice.example
    IA-->>RP: Subordinate Statement about Lattice (signed by IA)
    RP->>TA: GET /fetch?sub=https://health.gov.example
    TA-->>RP: Subordinate Statement about IA (signed by TA)
    RP->>RP: verify the chain bottom-up, apply policies,<br/>take the earliest exp
```

#### Verifying the chain

The resulting trust chain, a list of JWTs, is:

```text
[0] Lattice's Entity Configuration                 signed by Lattice's federation key (fed-1)
[1] health.gov's statement about Lattice           signed by health.gov's key
[2] federation.gov's statement about health.gov    signed by the Trust Anchor's key (known in advance)
```

**Verification runs from the top, which is the end you already trust:**

- Statement [2] is checked with the Trust Anchor's key, which the RP already has. Now `health.gov`'s keys are trusted.
- Statement [1] is checked with `health.gov`'s keys taken from [2]. Now Lattice's federation key `fed-1` is trusted.
- Statement [0] is checked with `fed-1` taken from [1]. Now Lattice's own metadata is trusted.
- The chain expires at the earliest `exp` in it, so trust is re-checked regularly.

If any link fails (a bad signature, an expired statement, or a superior that no longer issues a statement about you), the chain breaks and trust is gone. This is how revocation works: a superior simply stops vouching. Statements are short-lived, so removal spreads quickly without CRLs.

Leaves don't have to do all this fetching themselves. A federation can run a resolve endpoint that returns the already-verified chain and the final metadata in one call.

#### Who produces the chain

Each JWT in the chain is signed by a different entity, and the chain is simply those JWTs collected together.

| Piece                              | Produced (signed) by                  | Where it's published                                              |
| ---------------------------------- | ------------------------------------- | ----------------------------------------------------------------- |
| [0] Lattice's Entity Configuration | **Lattice** (self-signed)             | `https://op.lattice.example/.well-known/openid-federation`        |
| [1] Statement about Lattice        | **health.gov**                        | health.gov's fetch endpoint `?sub=https://op.lattice.example`     |
| [2] Statement about health.gov     | **federation.gov** (the Trust Anchor) | federation.gov's fetch endpoint `?sub=https://health.gov.example` |

Collecting the pieces into a chain is a separate job. Three different parties can do it:

- **The verifier assembles it.** This is the usual case. The party that wants to trust someone follows `authority_hints` upwards and fetches each piece, as in the sequence diagram above. When an unknown RP sends Lattice an authorization request, Authlete does this for Lattice.
- **The subject assembles it and presents it.** The RP fetches its own chain in advance and hands it over. Lattice's registration endpoint accepts exactly this: `POST /api/federation/register` with `Content-Type: application/trust-chain+json` (`FederationController.java`). This saves the verifier the network round trips.
- **A resolver assembles it.** A federation service with a resolve endpoint builds and verifies the chain, then returns the result.

Even when the subject hands over its own chain, the verifier still checks everything. It can't be faked: every piece carries a signature, and the top must be checked against a Trust Anchor key the verifier already has configured.

### Metadata policy: the ecosystem's rules, enforced automatically

Every superior in the chain can attach a `metadata_policy`. The policies are combined from the Trust Anchor down and then applied to the leaf's metadata. What comes out is the leaf's resolved metadata, the only metadata anyone actually uses.

| Operator      | Meaning                         | Example                                                         |
| ------------- | ------------------------------- | --------------------------------------------------------------- |
| `value`       | Force this value                | `"subject_type": {"value": "pairwise"}`                         |
| `default`     | Use this value if none is given | `"default_max_age": {"default": 3600}`                          |
| `add`         | Always include these            | `"contacts": {"add": ["soc@gov.example"]}`                      |
| `one_of`      | Must be one of these            | `"token_endpoint_auth_method": {"one_of": ["private_key_jwt"]}` |
| `subset_of`   | Keep only the allowed values    | Signing algorithms limited to `ES256` and `PS256`               |
| `superset_of` | Must include at least these     | Must support `S256` PKCE                                        |
| `essential`   | Must be present                 | `"jwks_uri": {"essential": true}`                               |

So a Trust Anchor can say "no RS256 anywhere in this federation" once, and it applies to every member automatically. A lower level can only tighten a rule from above, never loosen it. If two levels' policies conflict, the chain is invalid.

### How an RP registers with an OP

OpenID Federation offers two ways for an RP to start using an OP without manual setup.

#### Automatic registration (no registration step at all)

- The RP uses its Entity ID as its `client_id`.
- It sends a signed request object, so the authorization request proves it holds the RP's keys.
- The OP sees a `client_id` it has never seen before, builds the RP's trust chain up to a Trust Anchor it trusts, applies the policies, and checks the request signature against the resolved keys.
- If everything checks out, the flow continues as normal OIDC. The OP may cache the result until the chain expires.

#### Explicit registration (one call, then a normal client)

```mermaid
sequenceDiagram
    participant RP as Relying Party
    participant L as Lattice (FederationController)
    participant A as Authlete

    RP->>L: POST /api/federation/register<br/>Content-Type: application/entity-statement+jwt<br/>(its Entity Configuration)<br/>or application/trust-chain+json (a whole chain)
    L->>A: /federation/registration
    A->>A: resolve and verify the trust chain,<br/>apply metadata policy,<br/>register the client
    A-->>L: OK + entity statement
    L-->>RP: 200, application/entity-statement+jwt<br/>(registered metadata, client_id)
    RP->>L: normal OIDC flows with that client_id
```

The OP's response is itself a signed entity statement containing the metadata it actually registered. The registration expires along with the trust chain.

### Trust goes both ways

The RP uses the same process to check the OP: it resolves Lattice's chain to its own Trust Anchor before sending users there. That protects users from fake identity providers, which plain OIDC discovery doesn't, because discovery just believes whatever `/.well-known/openid-configuration` returns.

### Keys and rotation

- Federation keys (`jwks` in the Entity Configuration) sign federation statements. They're pinned by your superior, so rotating them means your superior publishing a new statement. Rotation should be rare and coordinated.
- Protocol keys (`jwks` / `jwks_uri` inside `metadata.openid_provider`) sign ID tokens and similar. They're protected by the chain, so you can rotate them freely by publishing new metadata.
- There's a historical keys endpoint, so old signatures can still be checked after a rotation.

### Endpoints a federation uses

| Endpoint                                | Who serves it            | Purpose                                        |
| --------------------------------------- | ------------------------ | ---------------------------------------------- |
| `/.well-known/openid-federation`        | Every entity             | Its own Entity Configuration                   |
| `federation_fetch_endpoint`             | Superiors                | Subordinate Statement about a given `sub`      |
| `federation_list_endpoint`              | Superiors                | List of the subordinates it vouches for        |
| `federation_resolve_endpoint`           | Usually TAs or resolvers | Returns a verified chain and resolved metadata |
| `federation_trust_mark_status_endpoint` | Trust Mark Issuers       | Is this trust mark still valid?                |
| `federation_registration_endpoint`      | OPs                      | Explicit client registration                   |
| `federation_historical_keys_endpoint`   | Any                      | Retired federation keys                        |

### How Lattice implements it

Lattice is a leaf entity that acts as an OP and a credential issuer. `FederationController.java` serves two endpoints:

| Endpoint                             | What our code does                                                                                                                                                                                 | What Authlete does                                                                                                                                                         |
| ------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `GET /.well-known/openid-federation` | Asks Authlete for the Entity Configuration with entity types `OPENID_PROVIDER` and `OPENID_CREDENTIAL_ISSUER`, and returns it as `application/entity-statement+jwt`                                | Builds and signs the JWT from the service settings: Entity ID, federation keys, `authority_hints`, metadata, trust marks                                                   |
| `POST /api/federation/register`      | Accepts only `application/entity-statement+jwt` (an RP's Entity Configuration) or `application/trust-chain+json` (a full chain); anything else gets 415. Passes it to Authlete and maps the result | Resolves the RP's trust chain, verifies every signature up to a configured Trust Anchor, applies the metadata policies, registers the client and returns the signed result |

`GET /.well-known/openid-federation` is Lattice publishing its Entity Configuration as a leaf.

```mermaid
flowchart TD
    TA["Trust Anchor<br/>(e.g. national directory)"]
    IA["Intermediate<br/>(e.g. a bank association)"]
    L["Lattice (OpenID Provider)<br/>publishes /.well-known/openid-federation"]
    RP["Client app (Relying Party)<br/>publishes its own entity configuration"]

    TA -->|signs statement about| IA
    IA -->|signs statement about| L
    TA -->|signs statement about| RP

    RP -. "POST /api/federation/register<br/>(entity configuration or trust chain)" .-> L
    L -. "verifies the chain up to the Trust Anchor,<br/>then registers the client automatically" .-> RP
```

- **Question it answers**: "Can I trust this organization (client or provider)?" A common authority vouches for it.
- **Direction**: Lattice is the provider. Clients prove they belong to the federation, and Lattice registers them automatically.
- **Endpoints**:
  - `GET /.well-known/openid-federation` returns Lattice's entity configuration, a signed JWT describing it as a provider and credential issuer.
  - `POST /api/federation/register` handles explicit registration: a client sends its entity configuration or trust chain, and Authlete verifies it and creates the client.
- **Code**: `FederationController.configuration()` and `register()`. Authlete does the verification.
- **Configured in**: the Authlete service settings (trust anchors, entity ID, keys), not the identity providers file.
- **Spec**: OpenID Federation 1.0.

### Appendix: how certificate validation works (X.509)

Federation chains and certificate chains share two phases that run in opposite directions:

- **Finding the chain goes bottom-up.** The client starts from the leaf, because that's all it has.
- **Trust flows top-down.** The root is the only thing trusted to begin with, so trust is passed down from it, one signature at a time.

#### Example: a browser visiting https://example.com

##### Phase 1: build the path, bottom-up

The server sends its certificate plus the intermediate (leaf first):

```text
example.com     issued by "R11"
R11             issued by "ISRG Root X1"
```

The browser follows the issuer names upwards:

- The leaf says its issuer is "R11", and that certificate was sent along.
- R11 says its issuer is "ISRG Root X1", and that one is in the trust store that ships with the OS or browser. The search stops there.

##### Phase 2: verify, trust flowing top-down

```mermaid
flowchart TD
    R["ISRG Root X1<br/>(in the trust store: trusted from the start)"]
    I["R11 intermediate"]
    L["example.com"]
    R -->|root's key verifies R11's signature<br/>so R11's key is now trusted| I
    I -->|R11's key verifies the leaf's signature<br/>so the leaf's key is now trusted| L
```

- The root's key checks the signature on R11's certificate, so R11's key can be trusted.
- R11's key checks the signature on the leaf certificate, so the leaf's key can be trusted.
- Then the leaf-specific checks: does the name match `example.com`, is it within its dates, is it allowed for TLS servers, has it been revoked?

#### In the JDK source

##### Phase 1: build the path (bottom-up)

In `SunCertPathBuilder.java`, `depthFirstSearchForward` starts at the leaf and looks up each certificate's issuer.

```java
// SunCertPathBuilder.java:269-296 (abridged)
builder.getMatchingCerts(currentState, buildParams.certStores());   // find candidate issuers
...
builder.verifyCert(cert, nextState, cpList);                        // quick checks on each candidate
...
if (builder.isPathCompleted(cert)) { ... }                          // line 316: reached a trust anchor?
...
depthFirstSearchForward(cert.getIssuerX500Principal(), nextState, ...); // line 540: recurse upward
```

The stopping test is `ForwardBuilder.isPathCompleted` (`ForwardBuilder.java:748`):

```java
for (TrustAnchor anchor : trustAnchors) {
    if (anchor.getTrustedCert() != null) {
        if (cert.equals(anchor.getTrustedCert())) {   // the cert IS a trusted root
            this.trustAnchor = anchor;
            return true;
        }
        ...
```

##### Phase 2: verify (trust flows top-down)

`PKIXCertPathValidator.validate` (`PKIXCertPathValidator.java:162`) is given one trust anchor and builds a list of checkers. `BasicChecker` is the key one:

```java
BasicChecker bc = new BasicChecker(anchor, params.date(), params.sigProvider(), false);
```

Its constructor seeds the "previous key" with the anchor's public key (`BasicChecker.java:83-93`):

```java
this.trustedPubKey = anchor.getTrustedCert().getPublicKey();
this.caName        = anchor.getTrustedCert().getSubjectX500Principal();
...
this.prevPubKey    = trustedPubKey;
```

`PKIXMasterCertPathValidator.validate` then walks the certificates in order, root side first (it takes a `reversedCertList`), and runs every checker on each. For each certificate, `BasicChecker.check` does this (lines 137-150):

```java
verifyValidity(currCert);       // cert.checkValidity(date)      — dates
verifyNameChaining(currCert);   // cert issuer DN must equal prevSubject
verifySignature(currCert);      // cert.verify(prevPubKey, ...)  — the key above verifies this cert
updateState(currCert);          // prevPubKey = currCert.getPublicKey(); prevSubject = currCert's subject
```

The initial "previous key" is the root's public key. The first certificate that gets checked is not the root.


### Why I'd still self-host rather than use the CDN:

| | Self-hosted (now) | Google Fonts CDN |
| --- | --- | --- |
| Privacy | No third party sees your users | Every visit to your sign-in page sends the user's IP to Google. A German court ruled this a GDPR violation in 2022. |


### Keyspace and brute-force resistance

A keyspace is the theoretical set of all keys an algorithm can use. For uniformly random binary keys of length `n` bits, the keyspace contains `2^n` possible keys. A larger keyspace makes exhaustive brute-force search more difficult, assuming keys are generated securely.

- **AES-128:** 2^128 possible keys, roughly 3.4 * 10^38.
- **AES-256:** 2^256 possible keys, roughly 1.1 * 10^77.

Because a 256-bit ECC key provides about the same security as a much larger 3072-bit RSA key (128 bits, per NIST SP 800-57), ECC offers significant performance advantages. For example, ECDSA with the P-256 curve is widely used in TLS and other protocols, providing strong security with smaller key sizes and faster computations.

When a cryptographic library executes an algorithm, the speed depends heavily on whether the operands fit cleanly inside the CPU's hardware registers.

- `ECC 256`: A 256-bit number is relatively small. It fits entirely into just four standard 64-bit CPU registers, or a single 256-bit SIMD register (AVX2's YMM registers). The CPU can execute arithmetic on these numbers using a highly optimized, short pipeline of micro-operations entirely within the CPU core, without constantly hitting the memory bus.
- `RSA 3072`: A 3072-bit integer is massive; it completely exceeds native hardware register capacities. To process it, the CPU must break the number down into an array of forty-eight 64-bit words and perform arbitrary-precision ("BigInteger") arithmetic. Multiplying two 3072-bit numbers requires thousands of CPU cycles, constant load/store instructions to shuttle data back and forth from memory, and heavy utilization of the instruction decoder just to manage the arrays.


`RSA (Modular Exponentiation)`: RSA operations rely on equations like $c \equiv m^e \pmod{n}$. Exponentiating a 3072-bit number requires a process called "repeated squaring and multiplication." Even with algorithmic shortcuts like the Chinese Remainder Theorem, the CPU is forced to perform computationally expensive, multi-word multiplications over and over again until the exponent is resolved.
- `ECC (Elliptic Curve Point Multiplication)`: ECC operations involve finding a point on a curve defined by $y^2 = x^3 + ax + b$. The mathematics of elliptic curves allows for much smaller numbers to be used while still providing equivalent security. At equal security, ECC signing and key generation are much faster than RSA's. Verification is the exception: RSA verifies with the small public exponent 65537, which is cheap, so RSA verification is usually faster than ECDSA verification.


`The mathematics of RSA require the resulting digital signature to be exactly the same size as the cryptographic modulus (the key size)`

- When you sign a token with a 3072-bit RSA key, the algorithm outputs a 3072-bit signature.
- In computer memory, 3072 bits translates to exactly 384 bytes of raw binary data.

An Elliptic Curve signature (like ECDSA used in ES256) consists of two distinct coordinates, commonly referred to as r and s. Each of these coordinates is the size of the curve itself.

- When you sign a token with a 256-bit ECC key, the algorithm outputs two 256-bit numbers, totaling 512 bits.
- In computer memory, 512 bits translates to exactly 64 bytes of raw binary data.

## The Base64Url Encoding Penalty

JWTs cannot be transmitted over HTTP as raw binary; they must be encoded into text using Base64Url. Base64Url encoding expands the size of binary data by roughly 33%. This is where the size difference explodes and severely impacts your server's HTTP traffic

## Elliptic curve keys: how they work

### The curve

An elliptic curve over a prime field is the set of points $(x, y)$ that satisfy

$$
y^2 \equiv x^3 + ax + b \pmod{p}
$$

The symbol $\equiv$ means "congruent": their difference is a multiple of $p$. Equivalently, both sides leave the same remainder from $0$ to $p - 1$ when divided by $p$. It is used instead of $=$ because the two sides usually only match after wrapping around $p$. For example, $6^2 = 36$, and $36 \equiv 2 \pmod{17}$ because $36 - 2 = 34$ is a multiple of 17.

**Formal definition.** Let $a, r, m \in \mathbb{Z}$ with $m > 0$. We write

$$
a \equiv r \pmod{m}
$$

if $m$ divides $a - r$, written $m \mid (a - r)$. In the example, $17 \mid (36 - 2)$ because $34 = 2 \times 17$. This is the same as saying $a$ and $r$ leave the same remainder from $0$ to $m - 1$ when divided by $m$.

**The remainder is not unique.** Any $r$ that differs from 2 by a multiple of 17 works too, so $36 \equiv 2 \equiv 19 \equiv -15 \pmod{17}$: $36 - 19 = 17$ and $36 - (-15) = 51 = 3 \times 17$. When a single value is wanted, the convention is the one from $0$ to $m - 1$, written $36 \bmod 17 = 2$.

Every coordinate is an integer from $0$ to $p - 1$. The curve also has one extra point, the **point at infinity** $\mathcal{O}$.

The points on the curve, together with the point at infinity, form a **group** under the addition rule. A group is closed: adding any two members gives another member. $\mathcal{O}$ is the group's zero: adding it to any point leaves that point unchanged.

### Adding points

Points can't be added by adding their coordinates. Over the real numbers the curve looks like a smooth, sideways bell, and addition is geometric. To compute $G + G = 2G$:

1. Draw the tangent line that touches the curve at $G$.
2. Extend it until it meets the curve again.
3. Reflect that point across the x-axis. The reflected point is $2G$.

To get $3G = 2G + G$, draw the line through $2G$ and $G$, find where it meets the curve, and reflect. In general, $P + Q$ is the reflection of the third point on the line through $P$ and $Q$.

Over a prime field the same rule is written with the line's slope $\lambda$, all mod $p$:

$$
\lambda = \frac{y_2 - y_1}{x_2 - x_1} \quad \text{(two different points)} \qquad
\lambda = \frac{3x_1^2 + a}{2y_1} \quad \text{(doubling)}
$$

$$
x_3 = \lambda^2 - x_1 - x_2 \qquad y_3 = \lambda(x_1 - x_3) - y_1
$$

On the toy curve below, doubling $G = (5, 1)$ gives $\lambda = 77 / 2 \equiv 13$, then $x_3 = 6$ and $y_3 = 3$: so $2G = (6, 3)$.

$k \times G$ means $G$ added to itself $k$ times. Nobody does $k$ additions: double-and-add reaches $k \times G$ in about $2 \log_2 k$ steps, by doubling and adding according to the bits of $k$.

### Why the modulus must be prime

The curve's addition rule divides: the slope of the line through two points is $\frac{y_2 - y_1}{x_2 - x_1}$. Modular arithmetic has no division, so "dividing by $a$" means multiplying by the **inverse** of $a$: the number $a^{-1}$ with $a \times a^{-1} \equiv 1 \pmod{p}$. When $p$ is prime, every non-zero number has an inverse. When it isn't, some don't.

**The trap of composite numbers.** Take a non-prime modulus such as 6. The numbers are 0 to 5. To find the inverse of 2, we need an $x$ with $2 \times x \equiv 1 \pmod{6}$:

| $x$ | $2 \times x$ | $\bmod 6$ |
| --: | --: | --: |
| 1 | 2 | 2 |
| 2 | 4 | 4 |
| 3 | 6 | **0** |
| 4 | 8 | 2 |
| 5 | 10 | 4 |

- **No inverse.** $2 \times x$ never equals 1, because 2 shares a factor with 6. So 2 has no inverse, and nothing can be divided by 2.
- **A zero divisor.** Worse, $2 \times 3 \equiv 0$: two non-zero numbers multiply to zero. Information is lost (you can't tell what was multiplied by 2 to get 0), equations that rely on division have no answer, and the curve's addition rule stops working. This breaks the algorithm itself, not just an attacker's attempts.

**The prime guarantee.** Now use a prime modulus such as 7. The numbers are 0 to 6. Find the inverse of 2 again:

| $x$ | $2 \times x$ | $\bmod 7$ |
| --: | --: | --: |
| 1 | 2 | 2 |
| 2 | 4 | 4 |
| 3 | 6 | 6 |
| 4 | 8 | **1** |

The inverse of 2 is 4. This isn't luck: a prime has no divisors other than 1 and itself, so no number from 1 to $p - 1$ shares a factor with it. That guarantees:

- every non-zero number has exactly one inverse, so division always works;
- no two non-zero numbers multiply to zero, so nothing collapses.

This holds for 7 and equally for the 256-bit prime behind P-256 (`secp256r1`). That is why the modulus of a curve is always prime: it keeps the addition rule, and with it the one-way function, well defined for every point.

### A toy example

Take

$$
y^2 \equiv x^3 + 2x + 2 \pmod{17}
$$

For each $x$ from 0 to 16, compute the right side and look for $y$ values whose square matches it. For $x = 0$ the right side is 2, and $6^2 \equiv 2$ and $11^2 \equiv 2$, so $(0, 6)$ and $(0, 11)$ are on the curve. Solutions come in pairs: $11 = 17 - 6$, and in general if $y$ is a solution then so is $p - y$.

```
x=0  → 2   → y = 6, 11
x=1  → 5   → none
x=2  → 14  → none
x=3  → 1   → y = 1, 16
x=4  → 6   → none
x=5  → 1   → y = 1, 16    ← G = (5, 1) is here
x=6  → 9   → y = 3, 14
x=7  → 2   → y = 6, 11
x=8  → 3   → none
x=9  → 1   → y = 1, 16
x=10 → 2   → y = 6, 11
x=11 → 12  → none
x=12 → 3   → none
x=13 → 15  → y = 7, 10
x=14 → 3   → none
x=15 → 7   → none
x=16 → 16  → y = 4, 13
```

Nine values of $x$ give two points each, so 18 points. With the point at infinity, the curve has **19 points**.

### Keys

Pick a fixed public point $G$, the **generator**. A key pair is

$$
P = k \times G
$$

where $k$ is a random integer (the **private key**) and $P$ is a point (the **public key**). Multiplying means adding $G$ to itself $k$ times with the curve's addition rule. $P$ can be published, for example in a JWKS; $k$ never leaves its owner.

On the toy curve with $G = (5, 1)$:

| $k$ | $k \times G$ | | $k$ | $k \times G$ |
| --: | :-- | --- | --: | :-- |
| 1 | $(5, 1)$ | | 11 | $(13, 10)$ |
| 2 | $(6, 3)$ | | 12 | $(0, 11)$ |
| 3 | $(10, 6)$ | | 13 | $(16, 4)$ |
| 4 | $(3, 1)$ | | 14 | $(9, 1)$ |
| 5 | $(9, 16)$ | | 15 | $(3, 16)$ |
| 6 | $(16, 13)$ | | 16 | $(10, 11)$ |
| 7 | $(0, 6)$ | | 17 | $(6, 14)$ |
| 8 | $(13, 7)$ | | 18 | $(5, 16)$ |
| 9 | $(7, 6)$ | | 19 | $\mathcal{O}$ |
| 10 | $(7, 11)$ | | | |

The list reaches the point at infinity at $19 \times G$ and then repeats, so 19 is the **order** of $G$. Because 19 is prime, $G$ visits every point on the curve once. Look at the $x$ values: 5, 6, 10, 3, 9, 16, 0, 13, ... They jump around with no visible pattern.

- **The point at infinity.** When $k$ is a multiple of the order, you get infinity (on the toy curve, $19 \times G = \mathcal{O}$). That is still a valid group element, but not a usable public key. Real private keys are chosen in the range $1$ to $n - 1$, so this never happens for them.
- **Wrapping.** After $19 \times G = \mathcal{O}$, the sequence repeats: $20 \times G = G$. So $k$ and $k + 19$ give the same point, which is why private keys are taken mod the order $n$.

### Why $k$ is hard to recover

**The trapdoor is the finite field.** Over the real numbers, the bouncing and reflecting could be traced backwards: points that are close stay close, so you could measure where the path went. Cryptography computes everything mod a large prime instead. Like clock arithmetic (10:00 plus 4 hours is 2:00, not 14:00), every value wraps around $p$: it is replaced by its remainder mod $p$, which is called **modular reduction**. Two things follow:

- the smooth curve becomes a scatter of seemingly random dots on a $p \times p$ grid, as the toy table shows;
- each time a value passes $p$ it wraps to the other side, so nearby points no longer stay near each other.

Given $G$ and a public point $P$, you see two dots in what looks like random static. The path between them isn't a line, and nothing records how many times it wrapped.

- **Forward is fast.** Double-and-add computes $k \times G$ with about 256 doublings and about 128 additions for a 256-bit $k$, which takes microseconds.
- **Backward is a search.** Given $P$ and $G$, nothing about $P$'s coordinates tells you how many additions produced it. There is no ordering or distance on the curve, and wrapping around $p$ scrambles any pattern. Finding $k$ is the **Elliptic Curve Discrete Logarithm Problem (ECDLP)**.
- **The best known attack** (Pollard's rho) takes about $\sqrt{n}$ steps, where $n$ is the order of $G$. For a 256-bit curve that is about $2^{128}$ steps, which is infeasible.
- **This is an assumption, not a proof.** No faster classical attack is known for well-chosen curves, but a large quantum computer running Shor's algorithm would break ECDLP. That is why post-quantum algorithms such as ML-KEM and ML-DSA are being standardized.

The naive attack computes $2G$, $3G$, $4G$, ... and compares each to $P$. On the toy curve that finishes after at most 18 tries. On P-256 the list has about $2^{256} \approx 1.2 \times 10^{77}$ entries, close to the number of atoms in the observable universe (about $10^{80}$). Even the best attack, at $2^{128}$ steps, is far out of reach.

### Real curves: P-256

P-256 (also called `secp256r1`, the curve behind `ES256` JWTs) has a prime $p$ of 256 bits and a generator $G$ whose order $n$ is about $2^{256}$. The private key is a random $k$ from $1$ to $n - 1$, and the public key is $k \times G$. With Pollard's rho costing about $2^{128}$ steps, P-256 is rated at **128-bit security**, comparable to AES-128 and RSA-3072, with far smaller keys and faster operations than RSA.

### ECDH: agreeing on a shared secret

Two parties, A and B, can agree on a secret over an open network without ever sending it.

1. **Generate key pairs.** Each picks a private scalar and computes its public point on the same curve:

   $$
   P_A = k_A \times G \qquad P_B = k_B \times G
   $$

2. **Exchange public keys.** An eavesdropper sees $P_A$, $P_B$, the curve and $G$, but can't recover $k_A$ or $k_B$ (ECDLP).
3. **Compute the shared secret.** Each side multiplies the *other's* public key by its *own* private scalar:

   $$
   S = k_A \times P_B = k_B \times P_A = (k_A k_B) \times G
   $$

4. **Validate the peer's key first.** Before step 3, an implementation must check that the received point is on the curve, in range and not the identity element, or an attacker can send a bad point to leak bits of $k$. The JDK does this in `ECDHKeyAgreement` (NIST SP 800-56A full public-key validation). For X25519 it rejects an all-zero result (`XDHKeyAgreement`: "Point has small order").

**Authentication is a separate problem.** Unauthenticated ECDH is open to a man-in-the-middle who substitutes their own public keys. TLS prevents this by having the server sign its handshake with its certificate key. The signature proves who sent the public key, not the key agreement itself.

### Deriving the traffic keys

The raw result of ECDH isn't used directly as an encryption key. By the standard it is the x-coordinate of $S$ (or the u-coordinate for X25519), which isn't uniformly random. It is fed into a key-derivation function:

- **TLS 1.3:** HKDF (HMAC-based), mixed with a hash of the handshake transcript. This gives separate keys for each direction and purpose.
- **TLS 1.2:** the TLS PRF (also HMAC-based), which first makes a master secret.

The outputs are symmetric keys for an AEAD cipher such as AES-GCM or ChaCha20-Poly1305. After that, both sides use fast symmetric encryption for the data.

### Static ECDH versus ECDHE

Static ECDH reuses the same private key across many connections, for months or years. ECDHE generates a new key pair for each handshake, on **both** the client and the server, and discards the private keys after the secrets are derived.

**The static-key risk.** An attacker records traffic for five years. If they steal the long-lived private key in year six, they can recompute the shared secret for every recorded session and decrypt it all. The JDK disables static `ECDH` and `TLS_RSA_*` suites by default in `jdk.tls.disabledAlgorithms`.

**How ECDHE gives forward secrecy:**

1. Each side generates a temporary key pair and exchanges the public keys. Both derive the same shared secret locally, then derive the traffic keys from it.
2. The temporary private keys and the shared secret are discarded after key establishment. The traffic keys stay in memory until the connection ends.
3. The server's certificate key only authenticates the handshake. It plays no part in deriving the traffic keys.
4. So if the certificate key leaks later, an attacker with a recording can't derive past traffic keys from it.

**In a TLS 1.3 handshake:**

1. Each side generates a fresh key pair and sends its public key. The server proves who it is by signing the handshake transcript, which includes both shares, with its long-term key (the `CertificateVerify` message).
2. Each side computes the same ECDH shared secret, then runs it through the key schedule (HKDF in 1.3) to get the session keys.
3. Each side discards the ephemeral private key and the shared secret. The session keys stay in memory until the connection closes.


Lattice is itself a client of Authlete's API. If you set `AUTHLETE_DPOP_KEY`, the token Lattice uses to call Authlete is DPoP-bound: [PlayAuthleteApiBase.java:80](app/com/lattice/oidc/client/PlayAuthleteApiBase.java#L80) loads the key, and [line 166](app/com/lattice/oidc/client/PlayAuthleteApiBase.java#L166) adds a freshly signed proof to every call. That's Lattice proving its identity to Authlete, separate from your apps' DPoP.


The heading shows the provider's `server.name` from the identity providers file. The demo's file comes from the test helper [FakeUpstreamProvider.java](test/com/lattice/oidc/handlers/FakeUpstreamProvider.java#L164), which writes `"name":"Upstream"`. "Upstream" there is just jargon for "the provider we sign in through".

```json
{ "id": "okta", "server": { "name": "Partner Inc (Okta)", "issuer": "https://partner.okta.com" },
  "domains": ["partner.example"], ... }
```

One database for all instances. As with Lattice, every Keycloak node connects to the same database (PostgreSQL, MySQL and others). Realms, clients, users, credentials and, since Keycloak 26, user sessions are stored there.

```scala
def apply[A](x: A | Null): Option[A] = if (x == null) None else Some(x)

final def orNull[A1 >: A | Null]: A1 = this.getOrElse(null)
```

Because the parameter is `A | Null`, passing a `String | Null` infers `A = String`:

```scala
//> using options -Yexplicit-nulls   (3.9.0)
val s: String | Null = System.getProperty("user.home")

val o: Option[String] = Option(s)   // ok
o.map(_.length)                     // ok, no .nn

val back = o.orNull                 // String | Null, no implicit evidence needed
```

What is authenticated is the token, not the person. When your API receives `Authorization: Bearer <token>`, it checks that the token is genuine. Either it verifies the signature, or it asks the authorization server through introspection

It also checks that the token hasn't expired or been revoked, and that it was issued for this API. That check is authentication in the narrow sense: it establishes the credential is real and came from the authorization server you trust

What the token proves is authorization.

What it does not prove:
- Who is sending the request. So a bearer token doesn't authenticate the sender at all. Sender-constrained tokens fix this. With DPoP (RFC 9449) or mutual-TLS-bound tokens (RFC 8705), the client must also prove it holds a private key the token is bound to. Then the token does authenticate the sender
- `That the user is present, or signed in just now`. The token may have been issued hours ago, or refreshed without the user involved. It records that the user granted access, not that they're at the keyboard.
- `That the user signed in to this app`. That's the ID token's job in OpenID Connect. An ID token is addressed to one client (`aud`) and says who signed in, when (`auth_time`) and how (`acr`).

The Authorization header doesn't help. In HTTP (RFC 9110), that header carries credentials, which is an authentication concept. The name predates OAuth. With OAuth, the credential it carries happens to be a grant of authorization.

the API authenticates the token, and the token tells it what has been authorized.

A JWT access token (RFC 9068) carries the grant inside it, signed by the authorization server. The API verifies the signature with the server's public key and reads the same fields from the token, with no call to the server.

A grant answers five questions:

| Question | Field in a JWT access token (RFC 9068) | Example |
| --- | --- | --- |
| Who gave the permission? | `sub` (the user) | `1001` |
| To which app? | `client_id` | `42` (Acme Notes) |
| To do what? | `scope` (or `authorization_details` for fine-grained rights) | `openid profile read:notes` |
| At which API? | `aud` (the resource server) | `https://notes.example/api` |
| Until when? | `exp`, plus `iat` for when it was issued | `10:30` |

A JWT access token is those answers, signed by the authorization server:
```json
{
  "iss": "https://lattice.example",
  "sub": "1001",
  "client_id": "42",
  "aud": "https://notes.example/api",
  "scope": "openid profile read:notes",
  "iat": 1791240600,
  "exp": 1791244200,
  "jti": "a1b2c3"
}
```

In RFC 6749, an authorization grant is the credential the client exchanges for tokens, not the permission itself. The grant types are those credentials

```sh
Consent  ──▶  Grant  ──▶  Access token
(a decision)  (the permission)  (a short-lived pass that carries it)
```

Consent: the user's decision
Consent is the moment Alice sees a screen like this and clicks Yes:

DevDashboard wants to:
✓ Read your profile
✓ Read your orders
[ Yes ] [ No ]

It's a human approving something. In Keycloak:
- The screen only appears if the client has "Consent required" turned on. It's off by default
- The decision is stored as a `UserConsentModel`. It records which client scopes this user approved for this client.

```java

package org.keycloak.models;

import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.keycloak.common.util.MultivaluedHashMap;


public class UserConsentModel {

    private final ClientModel client;
    private final Set<ClientScopeModel> clientScopes = new HashSet<>();
    private final MultivaluedHashMap<String, String> parameters = new MultivaluedHashMap<>();
    private Long createdDate;
    private Long lastUpdatedDate;

    public UserConsentModel(ClientModel client) {
        this.client = client;
    }

    public ClientModel getClient() {
        return client;
    }

    public void addGrantedClientScope(ClientScopeModel clientScope) {
        addGrantedClientScope(clientScope, null);
    }

    public void addGrantedClientScope(ClientScopeModel clientScope, String parameter) {
        if (clientScope.isAlwaysConsent()) {
            // always consent scopes are skipped
            return;
        }
        clientScopes.add(clientScope);
        if (ClientScopeModel.isParameterizedScope(clientScope)) {
            if (parameter == null) {
                throw new IllegalArgumentException("Parameter value is compulsory for Parameterized Scope " + clientScope.getName());
            }
            parameters.add(clientScope.getId(), parameter);
        }
    }

    public Set<ClientScopeModel> getGrantedClientScopes() {
        return clientScopes;
    }

    public List<String> getParameters(ClientScopeModel clientScope) {
        if (ClientScopeModel.isParameterizedScope(clientScope)) {
            return parameters.getList(clientScope.getId());
        }
        return Collections.emptyList();
    }

    public boolean isClientScopeGranted(ClientScopeModel clientScope) {
        return isClientScopeGranted(clientScope, null);
    }

    public boolean isClientScopeGranted(ClientScopeModel clientScope, String parameter) {
        for (ClientScopeModel apprClientScope : clientScopes) {
            if (apprClientScope.getId().equals(clientScope.getId())) {
                if (ClientScopeModel.isParameterizedScope(clientScope)) {
                    return parameter != null && parameters.getList(apprClientScope.getId()).contains(parameter);
                } else {
                    return parameter == null && parameters.getList(apprClientScope.getId()).isEmpty();
                }
            }
        }
        return false;
    }

    public Long getCreatedDate() {
        return createdDate;
    }

    public void setCreatedDate(Long createdDate) {
        this.createdDate = createdDate;
    }

    public Long getLastUpdatedDate() {
        return lastUpdatedDate;
    }

    public void setLastUpdatedDate(Long lastUpdatedDate) {
        this.lastUpdatedDate = lastUpdatedDate;
    }
}
```

## Grant: the permission itself
A grant is the authorization that exists as a result: "DevDashboard may read Alice's orders". It's the actual permission, which outlives any one token.
The OAuth spec uses "grant" in two related senses, which is why it's confusing.

1. Authorization grant (RFC 6749 §1.3): "a credential representing the resource owner's authorization". It's what the client hands in at the token endpoint to get tokens

The access token is derived from the grant.

```sh
POST /realms/myrealm/protocol/openid-connect/token

grant_type=authorization_code      ← the grant TYPE (a fixed label)
code=a8f3e2c1-77b0-4d...           ← the GRANT (the actual credential)
client_id=devdashboard
redirect_uri=https://...
```

1. ## Authorization code: web apps, SPAs, mobile apps

```sh
## get the grant. This happens in the browser,
GET $KC/auth?client_id=devdashboard
            &response_type=code
            &redirect_uri=https://dash.example/cb
            &scope=openid orders:read
            &state=xyz
            &code_challenge=E9Melhoa2Owv...&code_challenge_method=S256
```
The user logs in (and consents, if required). Keycloak redirects back:

```sh
https://dash.example/cb?code=a8f3e2c1-77b0.4f2e.9c1d...&state=xyz
                             └──────── the GRANT ────────┘
```

```sh
##  exchange it. The app's backend calls:
curl -X POST $KC/token \
  -u devdashboard:dash-secret \
  -d grant_type=authorization_code \
  -d code=a8f3e2c1-77b0.4f2e.9c1d... \
  -d redirect_uri=https://dash.example/cb \
  -d code_verifier=dBjftJeZ4CVP...
```

2. ## Refresh token: keeping the user logged in
This is always available to clients that got a refresh token earlier.

```sh
curl -X POST $KC/token \
  -u devdashboard:dash-secret \
  -d grant_type=refresh_token \
  -d refresh_token=eyJhbGciOiJIUzUxMiIs...
```  
- `grant_type=refresh_token` is the type.
- `refresh_token` is the grant: long-lived, tied to the user's Keycloak session.

3. ## Client credentials: service to service, no user

```sh
curl -X POST $KC/token \
  -u billing-job:job-secret \
  -d grant_type=client_credentials

```
- `grant_type=client_credentials` is the type.
- The grant is `-u billing-job:job-secret`

For stronger security, replace the secret with a signed JWT:

```sh
  -d client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer \
  -d client_assertion=eyJhbGciOiJSUzI1NiIs...
```  

4. ## Device code: TVs, CLIs, IoT
These are devices with no browser or keyboard. It's turned on by the client's OAuth 2.0 Device Authorization Grant setting.

Step A: the device asks for a code pair.
```sh
curl -X POST $KC/auth/device -d client_id=smart-tv -d scope=openid
```
The response:
```json
{ "device_code": "Uo3Kd8...",          ← the grant (kept secret, on the device)
  "user_code": "WDJB-MJHT",           ← shown on screen
  "verification_uri": "https://kc.example/realms/myrealm/device",
  "interval": 5, "expires_in": 600 }
```
The user opens that URL on their phone, logs in, and types `WDJB-MJHT`.

Step B: the device polls every 5 seconds.

```sh
curl -X POST $KC/token \
  -d client_id=smart-tv \
  -d grant_type=urn:ietf:params:oauth:grant-type:device_code \
  -d device_code=Uo3Kd8...
```
- The long `grant_type` URN is the type.
- `device_code` is the grant.

5. ## Token exchange: services calling services as the user

Scenario: a gateway receives Alice's token and needs a token for a downstream API, with a different audience and narrower scope. 

```sh
curl -X POST $KC/token \
  -u orders-gateway:gw-secret \
  -d grant_type=urn:ietf:params:oauth:grant-type:token-exchange \
  -d subject_token=eyJhbGciOiJSUzI1NiIs... \
  -d subject_token_type=urn:ietf:params:oauth:token-type:access_token \
  -d audience=inventory-api \
  -d scope=inventory:read
```  

- The `token-exchange` URN is the type.
- `subject_token` (Alice's existing access token) is the grant.

6. ## CIBA: approve on your phone
CIBA stands for Client-Initiated Backchannel Authentication. Example: a bank's call-centre app asks the customer to approve a login on their banking app. 

Step A: the client starts it, with no browser involved:
```sh
curl -X POST $KC/ext/ciba/auth \
  -u callcenter:cc-secret \
  -d scope=openid -d login_hint=alice -d binding_message="Approve login 4821"
```  
The response is `{ "auth_req_id": "1c266114-a1be...", "interval": 5 }`, and Alice gets a push notification.

Step B: the client polls.

```sh
curl -X POST $KC/token \
  -u callcenter:cc-secret \
  -d grant_type=urn:openid:params:grant-type:ciba \
  -d auth_req_id=1c266114-a1be...
```

`grant_type=urn:openid:params:grant-type:ciba` is the type and `auth_req_id` is the grant.

7. ## JWT bearer: trusting an assertion from another system
An external system signs a JWT about a user, and Keycloak trades it for its own token.

```sh
curl -X POST $KC/token \
  -u partner-app:secret \
  -d grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer \
  -d assertion=eyJhbGciOiJSUzI1NiIs...
```  

The `jwt-bearer` URN is the type and `assertion` (the signed JWT) is the grant


8. ## UMA ticket: fine-grained permissions (Authorization Services)
The app asks `"may Alice do view on resource invoice-42?"` and gets back an RPT, an access token containing the permissions that were granted.
```sh
curl -X POST $KC/token \
  -H "Authorization: Bearer <alice's access token>" \
  -d grant_type=urn:ietf:params:oauth:grant-type:uma-ticket \
  -d audience=invoices-api \
  -d permission=invoice-42#view
```
- The `uma-ticket` URN is the type.
- The grant is Alice's bearer token, plus a `ticket` if the resource server issued one.

9. ## Password: legacy, avoid
The app collects the user's password itself. It's turned on by the client's Direct access grants setting.
```sh
curl -X POST $KC/token \
  -d client_id=legacy-cli \
  -d grant_type=password \
  -d username=alice -d password=s3cret
```  
- `grant_type=password` is the type and `username + password` are the grant.


10. ## Pre-authorized code: digital credentials
This is part of OID4VCI, used for wallet apps and verifiable credentials: `grant_type=urn:ietf:params:oauth:grant-type:pre-authorized_code` with `pre-authorized_code=...`, which the credential issuer gave the wallet in its credential offer.

the grant type names the kind of proof, and the other parameter is the proof itself

```sh
urn:ietf:params:oauth:client-assertion-type:jwt-bearer 
urn:ietf:params:oauth:grant-type:jwt-bearer 
```   

## Client assertion: a replacement for the client secret
Recall that every token request has two parts: authenticate the client, then present the grant. A client assertion only changes the first part.

```sh
curl -X POST $KC/token \
  -d grant_type=client_credentials \                       ← grant type: unchanged
  -d client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer \
  -d client_assertion=eyJhbGciOiJSUzI1NiIs...              ← replaces client_secret
```  
The JWT the client signs, with its own private key:

```json
{
  "iss": "billing-job",          ← the client
  "sub": "billing-job",          ← the client again: "I am me"
  "aud": "https://kc.example/realms/myrealm",
  "jti": "5f1c9a...",            ← unique, so it can't be replayed
  "exp": 1760000060              ← lives for seconds
}
```
Keycloak checks the signature against the public key (or JWKS URL) registered on the client.

It works with any grant, because it only replaces `client_secret`:

```sh
-d grant_type=authorization_code -d code=...      -d client_assertion=...
-d grant_type=refresh_token      -d refresh_token=... -d client_assertion=...
```

## JWT bearer grant: the JWT is the permission
Here the JWT replaces the grant. It's typically a statement about a user, made by a system Keycloak trusts.

Scenario: a partner company has already logged Alice in on their side. Their system signs a JWT saying "this is Alice", and Keycloak trades it for a Keycloak token without sending Alice to a login page.

```sh
curl -X POST $KC/token \
  -u partner-app:secret \                                   ← client authentication (separate!)
  -d grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer \  ← grant type
  -d assertion=eyJhbGciOiJSUzI1NiIs...                      ← the grant
```  
The JWT, signed by the partner's identity system:
```json
{
  "iss": "https://idp.partner.com",   ← a third party, not the client
  "sub": "alice@partner.com",          ← a USER
  "aud": "https://kc.example/realms/myrealm",
  "exp": 1760000300
}
```

*They can appear in the same request*

Keycloak requires client authentication for the jwt-bearer grant: isConfidentialOnlyGrantType() returns true, as the comment there notes, even though the RFC makes it optional. So a high-security setup sends two different JWTs:
```sh
curl -X POST $KC/token \
  -d grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer \
  -d assertion=eyJ...ALICE...                       ← JWT #1: "this is Alice" (signed by partner IdP)
  -d client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer \
  -d client_assertion=eyJ...PARTNER-APP...          ← JWT #2: "I am partner-app" (signed by the client)
```

Every token request answers two questions

```sh
POST /token
┌──────────────────────────────────────────────┐
│ Part 1: WHO is the client?                   │  ← client authentication
│ Part 2: WHAT grant is it presenting?         │  ← grant_type + grant
└──────────────────────────────────────────────┘
```

Because the two parts are independent, a client authentication method can generally be combined with any grant type. The exceptions are grants that need a confidential client, such as client credentials, which a public client (no authentication at all) can't use.

With a client secret:
```sh
grant_type=authorization_code        ┐
code=a8f3e2c1...                     │ Part 2: the grant (identical)
redirect_uri=https://dash.example/cb ┘
client_id=devdashboard               ┐
client_secret=dash-secret            ┘ Part 1: "I'm devdashboard, here's my password"
```
With a signed JWT:

```sh
grant_type=authorization_code        ┐
code=a8f3e2c1...                     │ Part 2: the grant (identical)
redirect_uri=https://dash.example/cb ┘
client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer  ┐
client_assertion=eyJhbGciOiJSUzI1NiIs...                                      ┘ Part 1: "I'm devdashboard, here's my signature"
```

Alice writes Bob a cheque for $100. At the bank:

- The cheque is the grant. It proves Alice authorized paying $100 to Bob.
- Bob's ID card is the client authentication. It proves the person at the counter is Bob.
Neither works alone:
- ID without a cheque: the bank knows you're Bob, but nobody authorized paying you anything.
- Cheque without ID: if someone stole the cheque, they could cash it.
The bank checks both, and checks that they match: the cheque is made out to Bob, and you are Bob.

### The same thing at Keycloak's token endpoint

```sh
grant_type=authorization_code
code=a8f3e2c1...                ← the cheque: "Alice authorized devdashboard"
client_id=devdashboard
client_secret=dash-secret       ← the ID card: "I am devdashboard"
```

Public clients (SPAs, mobile apps), where there's no client authentication.

## Grants all look alike
Here are real values a client might send. Which is which?

```sh
a8f3e2c1-77b0.4f2e.9c1d.5b...      ← authorization code? device code? CIBA auth_req_id?
eyJhbGciOiJIUzUxMiIs...            ← refresh token? access token for exchange? jwt-bearer assertion?
```
You can't tell, and Keycloak couldn't reliably either:

- Codes, device codes and CIBA request IDs are all opaque random strings.
- Refresh tokens, access tokens and assertions are all JWTs.

*It tells Keycloak which parameters to *expect*
The parameters for each type differ completely:

```sh
authorization_code → code, redirect_uri, code_verifier
refresh_token      → refresh_token, scope
token-exchange     → subject_token, subject_token_type, audience, requested_token_type
device_code        → device_code
password           → username, password
```

*It lets Keycloak say no before looking at the grant*
An admin decides which grant types each client may use (the Capability config switches). That check needs only the type:
```sh
spa sends grant_type=password
→ "Direct access grants" is OFF for spa
→ rejected, and the username/password are never even checked
```
Event logs, client policies and FAPI rules also work at the type level. For example, a policy might say "token exchange only from these clients"


```sh
Client "dashboard-a" (configured: Client Id and Secret)
  grant_type=authorization_code, code=...,  client_secret=...         ✓

Client "dashboard-b" (configured: Signed JWT)
  grant_type=authorization_code, code=...,  client_assertion=eyJ...   ✓

Client "dashboard-a" sends client_assertion instead                    ✗ rejected
```

Duende IdentityServer labels each record in its grant store with one of these types (`IdentityServerConstants.PersistedGrantTypes`):

```c#
    public static class PersistedGrantTypes
    {
        public const string AuthorizationCode = "authorization_code";
        public const string BackChannelAuthenticationRequest = "ciba";
        public const string ReferenceToken = "reference_token";
        public const string RefreshToken = "refresh_token";
        public const string UserConsent = "user_consent";
        public const string DeviceCode = "device_code";
        public const string UserCode = "user_code";
    }
```

When the Resource Server (API) receives the token, it validates specific properties to authenticate the request itself:

- `Proof of Origin`: Verifying the signature (for a JWT) or querying the introspection endpoint (for an opaque token) proves the token was minted by your trusted identity infrastructure, not forged by an attacker.

- `Proof of Integrity`: For a JWT, the signature ensures that the scopes, user ID and expiration time haven't been altered. An opaque token carries none of these, so there is nothing to alter: the introspection response supplies them.

- `Proof of Audience`: Checking the aud claim ensures the request was intended for this specific API, preventing an attacker from taking a token meant for the Billing API and using it to authenticate a request to the HR API.

Think of a standard Bearer token like a concert ticket. The security guard at the door does not authenticate you—they don't check your ID or know your name. They authenticate the ticket by checking the watermark, the date, and the venue. Because the ticket is authentic, your request to enter is authenticated and granted.


RFC 6749 (§1.4) makes it clear that the token represents the grant of permission (authorization), not the identity of the user. When an API validates the token, it is validating the authorization.

It authenticates who created the token. Cryptographers call this data origin authentication, and it's a different thing from entity authentication

*How the signature proves who made the token*

- Only the authorization server has the private key. It signs the token's header and payload with it.
- Anyone can check the signature with the public key. The check passes only if the matching private key produced the signature over exactly those bytes.

Turning it into entity authentication
To authenticate the caller as well, bind the token to a key the client owns:
- `DPoP (RFC 9449)`. The token carries `cnf.jkt`, a hash of the client's public key. Each request includes a DPoP proof signed with the matching private key, so the API checks both who made the token and who is presenting it.
- `mTLS (RFC 8705)`. The token carries `cnf.x5t#S256`, a hash of the client's certificate. The client proves it holds that certificate's key during the TLS handshake.

RFC 4949 defines data-origin authentication as corroborating that received data came from its claimed source. It also states that a digital-signature mechanism can provide this service because a party without the private key cannot create a valid signature

```sh
Data-origin authentication
    Who originally produced this data?

Peer-entity authentication
    Who is communicating with me right now?
```

That distinction is crucial for bearer tokens. A JWT signature can authenticate the token’s origin, but it does not necessarily authenticate the party currently presenting it.

## NIST FIPS 186-5
NIST states that digital signatures are used both to:
- detect unauthorized modification of data; and
- authenticate the identity of the signatory.
That directly supports the concepts of integrity and origin authentication

A MAC provides data origin authentication and data integrity protection. MACs are used to authenticate both the source of a message and its integrity.

### Data Origin Authentication
The verification that information was generated by a system entity and has not been subsequently altered.

> Both signatures and MACs provide for integrity checking -- verifying that the
> message has not been modified since the integrity value was computed. However,
> MACs provide for origination identification only under specific circumstances.
> It can normally be assumed that a private key used for a signature is only in
> the hands of a single entity (although perhaps a distributed entity, in the
> case of replicated servers); however, a MAC key needs to be in the hands of
> all the entities that use it for integrity computation and checking.
> Validation of a MAC only provides corroboration that the message was generated
> by one of the parties that knows the symmetric MAC key. This means that
> origination can only be determined if a MAC key is known only to two entities
> and the recipient knows that it did not create the message. MAC validation
> cannot be used to prove origination to a third party.


### Docker image

The build makes the image with sbt-native-packager, which Play already uses for `stage` and `dist`. A fat JAR (sbt-assembly) isn't used: a Play app needs its `conf/` directory and several `reference.conf` files merged, which `stage` handles and an assembly JAR would need custom merge rules for.

```sh
sbt --client Docker/publishLocal      # build lattice-oidc:<version> into the local Docker daemon
sbt --client Docker/stage             # only write target/docker/stage (Dockerfile and files)
DOCKER_REGISTRY=ghcr.io DOCKER_USERNAME=reynaldjoabet sbt --client Docker/publish   # push amd64 + arm64
```

**What the settings in `build.sbt` do:**

| Setting | Why |
| --- | --- |
| `eclipse-temurin:25-jre-noble` base | A JRE (no compiler) on Ubuntu with glibc, the platform the JDK is built and tested on. Alpine's musl works for most apps but is a second, less-tested target. Pin a digest for releases. |
| `javacOptions --release 21` | The classes run on Java 21 or newer, whichever JDK compiled them. Without it, building on JDK 25 makes classes a Java 21 runtime can't load. |
| User `lattice`, UID 1001, group 0 | Not root. The numeric `USER 1001:0` lets Kubernetes' `runAsNonRoot` check it. |
| `UserGroupReadExecute` permissions | The app's files are read-only (`u=rX,g=rX`). They are still owned by `lattice`, which could `chmod` them back, so run with a read-only root filesystem (`--read-only`, or `readOnlyRootFilesystem` in Kubernetes) to make them truly unchangeable. |
| `JDK_JAVA_OPTIONS` | Always applied (the JVM logs a `Picked up JDK_JAVA_OPTIONS` line at start). `-Dpidfile.path=/dev/null` stops Play writing `RUNNING_PID` into the read-only app directory (it would fail to start), and `-Dlogger.resource=logback-container.xml` logs to stdout only. |
| `JAVA_OPTS` | Defaults an operator can replace: heap at 75% of the container's memory limit, and exit on `OutOfMemoryError` so the orchestrator restarts the container. |
| Port 9000 | Play's default `http.port`. |
| `tini` entrypoint | Recommended by the native-packager docs. The JVM isn't PID 1, so it responds to the signals used for thread and heap dumps, and `tini` forwards `SIGTERM` (Play then shuts down gracefully) and reaps orphaned processes. Installed from Ubuntu's packages, as root, before the user is created. See [Why `tini`](#why-tini-process-1-is-special-in-linux). |
| `no_version_check=1` | The start script otherwise runs `java -version` first, an extra JVM on every start, just to reject Java older than 8. |
| Tags | `<version>`, plus the 12-character commit in GitHub Actions. No `latest`: a deployment should name the exact image it runs. |
| OCI labels | Title, version, source repository and, in CI, the commit. |

#### Why `tini`: process 1 is special in Linux

Inside a container, the entrypoint runs as **PID 1**, the process Linux treats as `init`. PID 1 differs from every other process in two ways:

1. **Signals have no default action.** For a normal process, an unhandled `SIGTERM` terminates it. For PID 1, the kernel ignores any signal it hasn't installed a handler for. `docker stop` and Kubernetes send `SIGTERM`. If PID 1 ignores it, they wait out the grace period (10 seconds by default in Docker, 30 in Kubernetes), then send `SIGKILL`: no clean shutdown, and every stop or deploy is slow.
2. **It must reap orphans.** When a process exits after its parent, it's re-parented to PID 1, and PID 1 must collect its exit status (`wait()`). If PID 1 never does, those processes stay as **zombies**, filling the process table.

`tini` is a tiny init process, about 1 MB, written for exactly this job. It runs as PID 1 and starts the app as its child. It then:

- **forwards signals** (`SIGTERM`, `SIGINT`, `SIGQUIT` for thread dumps, and others) to the app, so they get handled;
- **reaps any zombie processes**;
- **exits with the app's exit code**, so the orchestrator sees why the app stopped.

**How much it matters for Lattice.** The start script that sbt-native-packager generates is a bash script, and it ends with `exec "$@"`, so bash replaces itself with `java`. Without `tini`, the JVM would be PID 1. The JVM does install its own `SIGTERM` handler, which runs shutdown hooks, so Play would still shut down cleanly. `tini` guards against the remaining cases:

- **The startup window:** before the `exec`, PID 1 is bash, which ignores `SIGTERM`. A stop during startup would hang until the grace period runs out.
- **Zombies:** the JVM never reaps orphaned processes. Lattice doesn't start subprocesses today, but anything that ever does would leak them.
- **Consistency:** `docker run --init` adds `tini`, but Kubernetes has no equivalent. Building `tini` into the image gives the same behaviour everywhere.

**How the build adds it.** `dockerCommands` inserts `USER root` and the `apt-get install tini` step into the final `mainstage` of the generated Dockerfile, directly after `FROM … AS mainstage`. Switching to root explicitly means the step doesn't depend on what the plugin writes next. The image still ends with `USER 1001:0`, so the app doesn't run as root. A `require` fails the build if `mainstage` is ever missing. Without it, the step would silently land in the discarded `stage0`, and the image would have no `tini`. `dockerEntrypoint` then puts `/usr/bin/tini --` in front of the start script; `--` ends `tini`'s own options, so arguments pass through to the app untouched. This relies on `apt-get`, so it suits Debian and Ubuntu bases only. On Alpine it would be `apk add --no-cache tini`, with the binary at `/sbin/tini`.

**What's deliberately left out:**

- **`-Djava.security.egd=file:/dev/./urandom`:** obsolete. Since JDK 9, `SecureRandom` on Linux doesn't block on `/dev/random`.
- **`-XX:+UseContainerSupport`:** on by default since JDK 10.
- **`-Dfile.encoding=UTF-8`:** the default since JDK 18 (JEP 400).
- **A fixed `-Xmx`:** it overrides `MaxRAMPercentage`, so the heap would no longer follow the container's limit.
- **`-XX:+ZGenerational`:** Java 21 needs it for generational ZGC, but JDK 24 removed the non-generational mode and ignores the flag with a warning. G1, the default, suits a request/response server.
- **A Docker `HEALTHCHECK`:** Kubernetes ignores it, and the image has no `curl`. Point the probes at `/health/live` and `/health/ready` instead.

**Running it:**

```sh
docker run --rm -p 9000:9000 --read-only --tmpfs /tmp \
  -e APPLICATION_SECRET=$(openssl rand -hex 32) \
  -e AUTHLETE_SERVICE_APIKEY=<id> -e AUTHLETE_SERVICE_ACCESSTOKEN=<token> \
  lattice-oidc:0.1.0-SNAPSHOT
```

`--read-only` keeps the container filesystem unchangeable. Play still needs somewhere for temporary files such as uploads, so `--tmpfs /tmp` gives it a writable `/tmp`. I haven't run this exact command, so test it before relying on it. For a full deployment, with PostgreSQL, Redis, TLS, monitoring and Kubernetes manifests, see [deploy/README.md](deploy/README.md).

A Docker image name has up to four parts:
```sh
ghcr.io / my-company / lattice-oidc : 0.1.0-SNAPSHOT
registry   namespace      image name     tag
```
```sh
dockerUsername := sys.env.get("DOCKER_USERNAME")//my company
```