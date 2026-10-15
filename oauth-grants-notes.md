# Access tokens and grants: notes

Notes on what access tokens prove and how grants work, with examples from Keycloak and Duende IdentityServer. The README's [Access tokens: what they prove](README.md#access-tokens-what-they-prove) section has the Lattice-specific version.

## Access tokens

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

### 1. Authorization code: web apps, SPAs, mobile apps

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

### 2. Refresh token: keeping the user logged in
This is always available to clients that got a refresh token earlier.

```sh
curl -X POST $KC/token \
  -u devdashboard:dash-secret \
  -d grant_type=refresh_token \
  -d refresh_token=eyJhbGciOiJIUzUxMiIs...
```  
- `grant_type=refresh_token` is the type.
- `refresh_token` is the grant: long-lived, tied to the user's Keycloak session.

### 3. Client credentials: service to service, no user

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

### 4. Device code: TVs, CLIs, IoT
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

### 5. Token exchange: services calling services as the user

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

### 6. CIBA: approve on your phone
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

### 7. JWT bearer: trusting an assertion from another system
An external system signs a JWT about a user, and Keycloak trades it for its own token.

```sh
curl -X POST $KC/token \
  -u partner-app:secret \
  -d grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer \
  -d assertion=eyJhbGciOiJSUzI1NiIs...
```  

The `jwt-bearer` URN is the type and `assertion` (the signed JWT) is the grant


### 8. UMA ticket: fine-grained permissions (Authorization Services)
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

### 9. Password: legacy, avoid
The app collects the user's password itself. It's turned on by the client's Direct access grants setting.
```sh
curl -X POST $KC/token \
  -d client_id=legacy-cli \
  -d grant_type=password \
  -d username=alice -d password=s3cret
```  
- `grant_type=password` is the type and `username + password` are the grant.


### 10. Pre-authorized code: digital credentials
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

## Keycloak storage

One database for all instances. As with Lattice, every Keycloak node connects to the same database (PostgreSQL, MySQL and others). Realms, clients, users, credentials and, since Keycloak 26, user sessions are stored there.
