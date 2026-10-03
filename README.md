# lattice-oidc

## Security fixes compared to the reference server

- JWT bearer and token exchange: the reference never checked the signature on JWT bearer assertions or JWT subject tokens, so a forged JWT got tokens. These are now verified against this server's own Authlete keys or a configured list of trusted issuers; anything else is rejected.
- Pairwise `sub`: computed as a keyed hash per site, so it's opaque and can't be linked across clients. The reference concatenated the sector and the user ID in plain text.
- ACR: an `acr` is only asserted if it's configured as satisfied by password login. The reference echoed back whatever the client asked for.
- Login: passwords are hashed with Argon2 and accounts lock after repeated failures. Response timing doesn't reveal which accounts exist.
- Sessions: a new session ID on every login, server-side invalidation on logout, and pending flows only completable by the browser that started them.
- Browser forms: protected against cross-site form posts (CSRF), with security headers and a CSP set throughout