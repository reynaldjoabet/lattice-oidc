# Grant Management for OAuth 2.0

Notes on Grant Management for OAuth 2.0, a FAPI working group specification, and how Lattice implements it with Authlete. Sources:
- the [specification](https://openid.net/specs/fapi-grant-management.html);
- [Authlete's article](https://developers.authlete.com/protocols-and-flows/advanced-flows/grant-management-for-oauth-2-0), written in 2021 for Authlete 2.3;
- the `authlete-java-common` 4.48 sources, which Lattice uses;
- Lattice's code.

Where the article and the library disagree, these notes follow the library.

## Why it exists

### The gap in OAuth's model

OAuth 2.0 (RFC 6749) has two kinds of object, but exposes only one:

- **Tokens** are what the client holds. They are short-lived, bearer or sender-constrained, and replaced constantly.
- **The grant**, the user's decision ("Alice allowed PayApp to read her current account"), is what every token is issued from. RFC 6749 never makes it addressable. It exists only as internal state at the authorization server: a consent record, a row linking user, client and scopes.

As long as the permission never changes, that's harmless: the client refreshes tokens, and the server quietly consults the grant. The gap appears as soon as the permission has a **lifecycle** of its own, and the client needs to act on it rather than on a token.

**1. Ambiguous incremental authorization.** When a client sends a second authorization request for the same user, RFC 6749 doesn't say whether that *extends* the existing grant, *replaces* it, or *creates a second one alongside it*. Each server decides:
- **Keycloak** accumulates consented scopes per user and client.
- **Google** merges only when the client sends its proprietary `include_granted_scopes=true`.
- **Other servers** treat each authorization independently.

The client can't state its intent, so it can't know what its new tokens cover without probing. Grant Management makes the intent explicit: `merge` extends, `replace` supersedes, `create` starts a separate grant.

**2. More than one grant per user and client.** In plain OAuth, the implicit key of a grant is the pair (user, client). Regulated data sharing often needs several independent permissions between the same user and the same app, each with its own scope, duration and purpose. Examples are a personal and a business account at one bank, or a 12-month data-sharing consent alongside a one-off payment authorization. Only an identifier per grant lets them coexist and be managed separately.

**3. Revocation at the wrong granularity.** Token revocation (RFC 7009) revokes a token. Whether that also ends the grant behind it is server policy: revoking a refresh token *may* cascade, and revoking an access token usually doesn't. A client that must stop all access the user gave (because the user withdrew consent in the client's own app, or the relationship ended) has no standard way to say "end this permission, everywhere". `DELETE` on the grant does exactly that, and takes every access and refresh token in it with it.

**4. The client's view drifts from the truth.** Permissions change without the client's involvement:
- the user withdraws consent at the bank's own dashboard;
- part of the permission expires;
- a regulator caps a consent's duration.

A client that tracks "what I'm allowed" in its own database gradually diverges from the server, which is the only authoritative source. A grant query returns the current, effective permission, including structured `authorization_details`, so the client can reconcile instead of guessing.

**5. Structured permissions make all of this sharper.** With Rich Authorization Requests (RFC 9396), a permission is no longer a list of scope strings, but structured data: these account IDs, these data clusters, this maximum amount, until this date. "Merge" and "replace" then need defined semantics, because two `authorization_details` arrays can't simply be unioned by string. Grant Management and RAR were developed in the same working group, FAPI, for this reason.

In short: OAuth answers "how does the client get and use a pass?"; Grant Management answers "how does the client manage the permission the passes come from?". The second question only matters when that permission is long-lived, specific, mutable and accountable.

### Where it's used, and where it isn't

**Where the need is real: regulated data sharing.** Open banking, and open finance more broadly, are where all five problems appear at once. A third-party provider (a budgeting app, a lender checking income, an accounting tool) holds long-lived access to specific accounts at a bank. Regulation requires that:
- **the customer can see and change** that consent;
- **the provider stops** when the customer withdraws, at either the bank or the provider;
- **the consent is auditable** as a distinct object with a lifecycle.

Every major scheme had to give consent an identity. They did it in two different ways:

| Pattern | How consent gets an identity | Examples |
| --- | --- | --- |
| **Consent resource first** | The provider creates a consent object through a scheme-specific API *before* authorization, then asks the user to authorize that object | UK Open Banking (`ConsentId`, sent as `openbanking_intent_id`); Berlin Group NextGenPSD2 in the EU (`consentId`); Open Finance Brasil (consent ID, carried in a `consent:` scope, which Lattice's Open Banking Brasil support handles) |
| **Grant ID from authorization** | Authorization itself creates the grant and returns its ID, which later requests refer to | Grant Management (`grant_id`); Australia's Consumer Data Right, whose `cdr_arrangement_id` identifies an arrangement that a later authorization can amend, and that either side can revoke |

The first pattern needs a proprietary consent API for every scheme. It fits payment initiation especially well, because the exact payment (amount, payee) must be fixed and validated *before* the user approves it. The second needs no extra API: the grant is created by an ordinary authorization request, so the same mechanism works across schemes and combines naturally with RAR. Grant Management is the standardised, scheme-independent form of the second pattern.

The row for the first pattern summarises how those schemes are documented. The Consumer Data Right comparison reflects my understanding of its standards, which I didn't recheck here. Grant Management itself is still a FAPI working group specification, not a final standard, and few authorization servers implement it. Authlete is one.

**Likely next: fields with the same shape.** Any domain where a user delegates long-lived, structured, revocable access to their data has the same needs:
- **open finance beyond bank accounts:** pensions, insurance, investments;
- **energy data:** Australia's Consumer Data Right already extends beyond banking to energy;
- **healthcare data sharing**, where consent is specific, time-limited and must be withdrawable;
- **AI agents acting for a user:** they need delegated authority that can be extended step by step, inspected and withdrawn without re-consenting to everything. That fits Grant Management's model, but it's a natural fit, not established practice.

**Where it isn't needed.** Signing in, first-party apps, and machine-to-machine access with client credentials. There the permission is "this app may know who I am" or a fixed set of scopes that never changes, so there's nothing to merge, replace, query or withdraw beyond what token revocation and session logout already do. For almost every OpenID Connect deployment, Grant Management is unnecessary, and the right choice is to leave it off.

## The three request actions

A client adds two parameters to an ordinary authorization request (or a CIBA or device authorization request):

| `grant_management_action` | `grant_id` | Effect |
| --- | --- | --- |
| `create` | must be absent | A new grant. The token response returns its `grant_id`. |
| `merge` | required | Add this request's permissions to the existing grant. The new tokens carry everything granted so far. (Earlier drafts called this `update`.) |
| `replace` | required | Withdraw what the grant held, and keep only this request's permissions. |

Authlete rejects inconsistent combinations: `merge` or `replace` without a `grant_id`, a `grant_id` without an action, or a `grant_id` with `create`.

**Example: an app asks for more.** In March, the app created a grant for account A:

```http
GET /api/authorization?response_type=code&client_id=payapp
    &scope=openid accounts
    &authorization_details=[{"type":"account_information","accounts":["A"]}]
    &grant_management_action=create
```

The token response includes the new grant's ID:

```json
{
  "access_token": "SlAV32hkKG",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "8xLOxBtZp8",
  "grant_id": "TSdqirmAxDa0_-DB_1bBMVOhKz9I6IkKzCNo-bx5xT2"
}
```

In June, the customer adds account B, and the app merges it into the same grant:

```http
GET /api/authorization?response_type=code&client_id=payapp
    &scope=openid accounts
    &authorization_details=[{"type":"account_information","accounts":["B"]}]
    &grant_management_action=merge
    &grant_id=TSdqirmAxDa0_-DB_1bBMVOhKz9I6IkKzCNo-bx5xT2
```

The new access token now covers A and B. With `replace` instead of `merge`, it would cover only B, and A would be withdrawn.

## The Grant Management endpoint

The authorization server exposes one more URL, with two operations. Lattice serves it at `/api/gm/{grant_id}`:

| Operation | Request | Needs an access token with scope | Success |
| --- | --- | --- | --- |
| Query | `GET /api/gm/{grant_id}` | `grant_management_query` | `200`, the grant as JSON |
| Revoke | `DELETE /api/gm/{grant_id}` | `grant_management_revoke` | `204 No Content` |

The access token is sent as usual (`Authorization: Bearer …`, or DPoP with a `DPoP` proof, or bound to a client certificate). The token must belong to the client that holds the grant. The specification also restricts Grant Management to confidential clients.

**A query response** has three parts:

```json
{
  "scopes": [
    { "scope": "openid accounts", "resource": ["https://api.bank.example"] }
  ],
  "claims": ["email", "name"],
  "authorization_details": [
    { "type": "account_information", "accounts": ["A", "B"] }
  ]
}
```

- **`scopes`:** groups of scopes, each with the resources (RFC 8707) they were granted for. Groups with the same resources are merged, and the list is sorted by resource.
- **`claims`:** every claim the user consented to across the grant, deduplicated and sorted. This is why Lattice passes `consentedClaims` (see below).
- **`authorization_details`:** the RFC 9396 details, deduplicated. Authlete compares them by hash, so spacing and key order don't create duplicates.

**A revocation** deletes every access token and refresh token in the grant. That works for Authlete's default, opaque (handle) access tokens. A **JWT access token** stays valid until it expires, because an API can verify it without asking anyone, unless the API also checks with the server (see [Opaque or JWT](README.md#opaque-or-jwt-where-the-permission-is-written)).

## A database schema for grants

[docs/grant-management/grants.sql](docs/grant-management/grants.sql) is a PostgreSQL schema for an authorization server that stores grants itself, following draft-03 of the specification section by section. Lattice doesn't use it, because Authlete stores Lattice's grants; it shows what the specification asks a server to keep:
- **`grants`:** the grant itself, with a random, public `grant_id`. It's `pending` until its tokens are claimed, and records the timestamps and `updated_by` of the query response. Several grants per client and user are allowed.
- **Scopes, claims and authorization details:** stored as separate rows, so `merge` is an insert and `replace` a delete and an insert. Authorization details are deduplicated by their canonical `jsonb` form.
- **Tokens:** stored as hashes and linked to their grant, so a revocation, `merge` or `replace` can invalidate them.
- **History:** for audit, since the API itself provides none.
- **`grant_resource(grant_id)`:** builds the exact JSON of a query response.

The file ends with every operation (create, activate, merge, replace, query, revoke and cleanup) on sample data, in a transaction that is rolled back. Run it with `psql -f grants.sql`.

## What a grant is, inside Authlete

- **A grant is a set of live token records.** Every access token issued under a grant ID is one record, live while its access or refresh token hasn't expired. Records drop out as they expire, with no action from anyone: a grant can shrink by itself.
- **Merged permissions are a snapshot.** A token issued by `merge` stores an encrypted copy of the grant's permissions at the time of issue. If older records later expire or are deleted, the snapshot doesn't change.
- **Access and refresh tokens come in pairs.** Each access token has at most one refresh token, and the other way round. Deleting one deletes the other.
- **Introspection:** to see the grant behind a token, use Authlete's own `/auth/introspection` API rather than standard RFC 7662 introspection. It returns `grantId` and `grant`, accepts a `resources` parameter, and checks scopes and resources per group.

## Who does what

| Step | Lattice | Authlete |
| --- | --- | --- |
| Authorization request with `grant_management_action` | Forwards the request unchanged (`/auth/authorization`) | Validates the parameters, looks up the grant, returns its owner as `grantSubject` |
| Sign-in and consent | Authenticates the user; **refuses a `merge` or `replace` of another user's grant** | |
| Issuing (`/auth/authorization/issue`, CIBA `/backchannel/authentication/complete`, `/device/complete`) | Sends the released claims, **and their names as `consentedClaims`** | Records the permissions under the grant ID |
| Token request | Forwards it (`/auth/token`) | Returns `grant_id` in the token response |
| `GET` / `DELETE /api/gm/{grant_id}` | `GrantManagementController`: passes the token, DPoP proof, client certificate, `htm` and `htu` to `/gm`, and turns the action into an HTTP response | Checks the token, its scope and its client; returns or revokes the grant |

### Three refinements in Lattice

Comparing Lattice with Authlete's article and the library led to three changes:

1. **Error responses (`GrantManagementController`).** For every error, Authlete's response content is a `WWW-Authenticate` value, for example `Bearer error="invalid_token", error_description="…"`, or `DPoP error="use_dpop_nonce"`. Lattice used to send it as the response body, labelled `application/json`, with no `WWW-Authenticate` header, so clients couldn't read the error and DPoP clients never saw the nonce challenge. It now sends 401, 403 and 404 with the challenge in `WWW-Authenticate` and no body (RFC 6750), as the UserInfo endpoint does. `CALLER_ERROR` (a mistake in Lattice's call) and `AUTHLETE_ERROR` are logged, and the client gets a generic `server_error`, without Authlete's internal message.

2. **Another user's grant (`AuthorizationHandler`).** When the person who signs in isn't the grant's owner, Authlete *silently skips* grant management: it issues tokens anyway, outside the grant the client asked to change. Lattice now compares the signed-in user with `grantSubject` and refuses with `DIFFERENT_SUBJECT`, the same reason it gives when a client asks for one user and another signs in. The client receives an error, not tokens it didn't ask for.

3. **Consented claims (`AuthorizationHandler`, `CibaHandler`, `DeviceHandler`).** If `consentedClaims` is omitted, Authlete works out the consented claims from the scopes and the `claims` parameter, which can be wrong: a claim that was requested but has no value isn't released. Lattice now passes the names of the claims it actually released, so a grant query's `claims` matches what the user saw and allowed.

Tests: `GrantManagementTest` (query, revoke, the three error challenges, the DPoP nonce, hidden internal errors), and three new tests in `AuthorizationFlowTest` (consented claims, another user's grant refused, your own grant issued).

## Setting it up in Authlete

**Server deployment (self-hosted):** `feature.gm.enabled=true` in `authlete-server.properties`. Without it, Authlete omits the metadata, ignores the request parameters, and refuses `/gm` calls.

**Service settings:**

| Console setting | Property | Published in discovery as |
| --- | --- | --- |
| Grant Management Endpoint: `https://<lattice>/api/gm` | `grantManagementEndpoint` | `grant_management_endpoint` |
| Grant Management Action Required | `grantManagementActionRequired` | `grant_management_action_required` |

- **Supported actions** are published as `grant_management_actions_supported`. With an endpoint configured, that's `create`, `query`, `replace`, `revoke` and `merge`; without one, only `create`, `replace` and `merge`.
- **"Action required"** makes every authorization request carry a `grant_management_action`, and then public clients are refused at the authorization endpoint.
- **The endpoint URL must be Lattice's,** because clients read it from discovery. Authlete also uses it to compute the expected `htu` of DPoP proofs.

**Scopes:** register `grant_management_query` and `grant_management_revoke` as scopes clients may request. A client gets them like any other scope, in an authorization request, and uses the resulting access token at the endpoint.

## Where Authlete departs from the specification

From Authlete's article. Some may have changed since Authlete 2.3, so check them against your version:

- **`grant_id` in the token response:** returned only when the request carried a `grant_management_action`. The specification says it should be returned whenever the server supports any action.
- **No grant ID from the authorization endpoint:** even when an access token is issued there directly (implicit or hybrid flows).
- **Another user's grant:** skipped silently rather than refused. Lattice now refuses (refinement 2 above).
- **`replace`:** how it should treat existing tokens was an open question in the working group (FAPI issue 454) when the article was written.

## How it relates to Lattice's other "grant" features

| | Grant Management revoke | Account page: "Remove access" | Remembered consent (`AppConsentStore`) |
| --- | --- | --- | --- |
| Who uses it | The client, through the API | The user, on Lattice's account page | Lattice itself |
| What it removes | One grant (one `grant_id`) and its tokens | Every token the app holds for this user (Authlete's client authorization), and the remembered consent | Nothing: it only skips the consent page next time |
| Where it lives | Authlete | Authlete, plus Lattice's consent record | Lattice |

A client may hold several grants for the same user. Grant Management revokes one of them; "Remove access" ends the app's access entirely.
