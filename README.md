# lattice-oidc

## Security fixes compared to the reference server

- JWT bearer and token exchange: the reference never checked the signature on JWT bearer assertions or JWT subject tokens, so a forged JWT got tokens. These are now verified against this server's own Authlete keys or a configured list of trusted issuers; anything else is rejected.
- Pairwise `sub`: computed as a keyed hash per site, so it's opaque and can't be linked across clients. The reference concatenated the sector and the user ID in plain text.
- ACR: an `acr` is only asserted if it's configured as satisfied by password login. The reference echoed back whatever the client asked for.
- Login: passwords are hashed with Argon2 and accounts lock after repeated failures. Response timing doesn't reveal which accounts exist.
- Sessions: a new session ID on every login, server-side invalidation on logout, and pending flows only completable by the browser that started them.
- Browser forms: protected against cross-site form posts (CSRF), with security headers and a CSP set throughout


### Pairwise sub: a keyed hash instead of plain concatenation
What pairwise means (OIDC Core §8.1). A client registered with `subject_type=pairwise` should get a different sub for the same user than every other client, so that two sites can't compare notes and work out that they share a user.

The reference built sub as `"PAIRWISE-" + sectorIdentifier + "-" + userId`, for example `PAIRWISE-shop.example-1001`. The real user ID sits inside the string, so any two clients can strip the prefix and correlate users. It also leaks the internal user ID.

Now `(PairwiseSubjects): sub = base64url(HMAC-SHA256(secret, sector + "|" + userId))`

- Stable: the same user on the same site always gets the same value.
- Unlinkable: different sites get unrelated values.
- Not reversible without the server's secret (`PAIRWISE_SECRET`, falling back to the app secret)


### Login: Argon2 hashing, lockout, and no account enumeration
- Argon2 hashing, a memory-hard algorithm that makes offline cracking expensive. Demo passwords are hashed when the store loads; nothing is stored in plain text.
- Lockout: after `lattice.login.max-failures` wrong passwords (default 5), that login ID is locked for `lattice.login.lockout` (15 minutes). While it's locked, even the correct password is refused, so an attacker can't keep guessing. The user sees "Too many failed attempts".

### Sessions: rotation, real logout, and pending flows tied to one browser
Session ID rotation (`UserSessions.login`). Every successful login creates a brand-new session ID (`sid`). This prevents session fixation, where an attacker plants a known session ID in the victim's browser before they log in and then rides on it afterwards.

Server-side invalidation. Play's session cookie is signed, but anyone holding a copy can replay it. So the cookie only carries the `sid`, and a session counts as valid only while that `sid` is registered on the server. Logout removes it there, so a stolen or replayed copy of the old cookie stops working. A test checks this. The `sid` is also what back-channel logout and native SSO key on.

Pending flows bound to the browser (`Interactions`). Each browser gets a stable random ID (`bid`) in its cookie. Pending consent, device-approval and federation-login state is stored server-side under its ticket or code and tagged with that `bid`. Completing a flow requires the same `bid`. That stops an attacker who learns or guesses a ticket from completing the consent or device approval from their own browser, and it stops cross-site requests from finishing someone else's flow. CSRF tokens on the forms add a second layer.

- `Single use`. The ticket is removed when it's used, so a replayed decision fails. That's tested too.


### Project structure
```sh
com.lattice.oidc
├── controllers/   thin Play controllers, one per spec area; routes point here
│                  BaseController (today's AuthleteController), Authorization, Token,
│                  UserInfo, Introspection, Revocation, Par, ClientRegistration,
│                  GrantManagement, Discovery, Ciba, Device, Credential, CredentialOffer,
│                  Federation, Obb, Logout, Health, Test
├── handlers/      protocol logic: AuthorizationHandler, TokenGrantHandler (exchange/JWT bearer),
│                  NativeSsoHandler, CibaHandler, DeviceHandler, CredentialOrderHandler,
│                  ObbDcrHandler, ObbTokenHandler, LogoutHandler
├── models/        AuthorizationPage, AuthorizationInteraction, Consent, User, FederationConfig, ...
├── security/      LoginService, UserSessions, Interactions, JwtVerifier, PairwiseSubjects,
│                  ObbCertValidator, AuditService (new)
├── stores/        UserStore, InMemoryUserStore, ConsentStore
├── client/        Authlete Play WS client (unchanged)
├── filters/       Filters, RequestIdFilter, HstsFilter, AccessLogFilter (new)
├── common/        Requests, Responses, Jsons, WebException, ErrorHandler (new), LatticeConfig
└── modules/       AuthleteModule
```