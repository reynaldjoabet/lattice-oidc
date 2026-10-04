# Design and screens

Designs for every end-user and operator screen of Lattice. The screenshots below are rendered from the design canvas; the editable source lives in the canvas ([Lattice OIDC screens](https://claude.ai/artifact/CRds8ufKFuZjJGn3n1aqBB), private until shared).

Screens 01–15 are implemented; the last column of their tables names the template and endpoint behind each one. Screens 16–38 are designs for the next features and are not built yet.

## Design language

| Element | Choice |
| ------- | ------ |
| Logo | Hexagonal lattice: six atoms around a central identity atom ([`public/images/concept-c-hex-lattice.svg`](../../public/images/concept-c-hex-lattice.svg)) |
| Accent | `#3b5bdb` (`--accent` in `oidc.css`); hover `#2c46b0` |
| Identity | `#ffb547` amber: the logo's centre atom and the signed-in user's avatar |
| Text | `#1b1f2a` primary, `#5b6170` secondary (6:1 on white) |
| Background | `#f3f4f7` with a faint dot grid, a nod to the lattice |
| Type | IBM Plex Sans for text, IBM Plex Mono for codes and identifiers |
| Layout | One white card, max 440 px wide, 16 px radius; the operator console uses a sidebar layout |
| Controls | 44 px touch targets; primary action on the right (Deny · Allow) |

Rules that every screen follows:

- **Plain language first.** Scopes and claims read as "See your basic profile"; protocol terms sit under *Technical details*.
- **Codes are shown to be matched, not just typed.** The device code, CIBA binding message and wallet transaction code all appear in a large monospace panel with "check it matches" text.
- **Real messages.** Error and lockout texts are the exact strings the server returns.
- **Placeholders in brackets** (`[binding message]`, `[request ID]`, `[count]`) mark values that come from the server at runtime. "Acme Notes", "Example Bank" and "Acme Budget" are example client apps.

## Sign-in and consent

| Screen | Purpose | Flow | Implemented in |
| ------ | ------- | ---- | ------ |
| 01 Sign in | Password sign-in plus "continue with" upstream providers | Authorization code (`/api/authorization`), identity brokering | `signIn.scala.html` (step 1 of 2) |
| 02 Sign in: locked | Shown after `lattice.login.max-failures` wrong passwords | Same | `signIn.scala.html`, error state |
| 03 Consent | What the app gets, in plain language; switch account | Authorization decision (`/api/authorization/decision`) | `authorization.scala.html` (step 2 of 2) |
| 04 Link accounts | A brokered sign-in matches an existing account's email; confirm with the password | Identity brokering callback, `POST /api/federation/link` | `accountLink.scala.html`, `IdentityLinkStore` |

<table>
  <tr>
    <td><img src="01-sign-in.png" width="240" alt="01 Sign in"></td>
    <td><img src="02-sign-in-locked.png" width="240" alt="02 Sign in: locked"></td>
    <td><img src="03-consent.png" width="240" alt="03 Consent"></td>
    <td><img src="04-link-accounts.png" width="240" alt="04 Link accounts"></td>
  </tr>
</table>

## Devices and decoupled sign-in

| Screen | Purpose | Flow | Implemented in |
| ------ | ------- | ---- | ------ |
| 05 Enter code | Type the code a TV or console shows | Device flow (RFC 8628), `/api/device/verification` | `deviceVerification.scala.html` |
| 06 Confirm device | Match the code, see what the device gets | `/api/device/complete` | `deviceAuthorization.scala.html` |
| 07 Device connected | Success, with a pointer to removing the device | Same | `message.scala.html` (success) |
| 08 Approve sign-in | Approve a sign-in started on another device; binding message and countdown | CIBA with `lattice.ciba.mode = builtin`: `GET /ciba`, `POST /ciba/decision` | `cibaApproval.scala.html`; the simulator modes remain |

<table>
  <tr>
    <td><img src="05-device-enter-code.png" width="240" alt="05 Enter code"></td>
    <td><img src="06-device-confirm.png" width="240" alt="06 Confirm device"></td>
    <td><img src="07-device-connected.png" width="240" alt="07 Device connected"></td>
    <td><img src="08-approve-sign-in-ciba.png" width="240" alt="08 Approve sign-in"></td>
  </tr>
</table>

## Session and account

| Screen | Purpose | Flow | Implemented in |
| ------ | ------- | ---- | ------ |
| 09 Sign out? | Confirm when the logout request has no matching `id_token_hint`; lists the apps that will be signed out | RP-initiated logout (`/api/logout`) | `logoutConfirm.scala.html` |
| 10 Signed out | Confirmation, with a return link to the app | Same, with back-channel logout | `message.scala.html` (success) |
| 11 Account | Connected apps (removable), sign-in methods, waiting CIBA requests | `GET /account`, `POST /account/apps/:clientId/remove` (Authlete client authorizations) | `account.scala.html`, `login.scala.html` |
| 12 Request expired | Expired or foreign-browser request, with a request ID for support | Any browser flow | `message.scala.html` / `error.scala.html` |

<table>
  <tr>
    <td><img src="09-sign-out.png" width="240" alt="09 Sign out?"></td>
    <td><img src="10-signed-out.png" width="240" alt="10 Signed out"></td>
    <td><img src="11-account-connected-apps.png" width="240" alt="11 Account"></td>
    <td><img src="12-error-request-expired.png" width="240" alt="12 Request expired"></td>
  </tr>
</table>

## Wallets and open banking

| Screen | Purpose | Flow | Implemented in |
| ------ | ------- | ---- | ------ |
| 13 Credential offer | Scan a QR code or open the wallet; shows the transaction code | OpenID4VCI credential offer (`POST /api/offer/issue`) | `credentialOfferResult.scala.html`, QR via `QrCodes` (qrcodegen) |
| 14 Open banking consent | The account, each permission and the expiry | Open Banking Brasil consents (`consent:` scope) | `authorization.scala.html` with `ObbConsentView` |

<table>
  <tr>
    <td><img src="13-credential-offer-wallet.png" width="240" alt="13 Credential offer"></td>
    <td><img src="14-open-banking-consent.png" width="240" alt="14 Open banking consent"></td>
  </tr>
</table>

## Operator console

| Screen | Purpose | Implemented in |
| ------ | ------- | ------ |
| 15 Overview | Authlete status, active sessions, identity providers, accounts with failed logins, the six caches (sizes and hit rates from `record-stats`) and recent audit events | `GET /admin`, `admin.scala.html`; only login IDs in `lattice.admin.login-ids` (`ADMIN_LOGIN_IDS`) |

<img src="15-operator-console.png" width="720" alt="15 Operator console">

## Passkeys (designed)

| Screen | Purpose |
| ------ | ------- |
| 16 Sign in with a passkey | The Login ID field offers saved passkeys (WebAuthn conditional UI); password and providers stay one click away |
| 17 Passkey prompt | Waiting for Touch ID, Face ID, Windows Hello or a security key, with a password fallback |
| 18 Offer a passkey | After a password sign-in, at most once a week: benefits, create or skip |
| 19 Passkey created | Success, with an editable name |
| 20 Account: passkeys | Each passkey with type (synced or device-only), last use and Manage |

<table>
  <tr>
    <td><img src="16-sign-in-with-a-passkey.png" width="240" alt="16 sign in with a passkey"></td>
    <td><img src="17-passkey-prompt.png" width="240" alt="17 passkey prompt"></td>
    <td><img src="18-offer-a-passkey.png" width="240" alt="18 offer a passkey"></td>
    <td><img src="19-passkey-created.png" width="240" alt="19 passkey created"></td>
  </tr>
</table>

<table>
  <tr>
    <td><img src="20-account-passkeys.png" width="240" alt="20 account passkeys"></td>
  </tr>
</table>

## Step-up and secure approvals (designed)

| Screen | Purpose |
| ------ | ------- |
| 21 Remove a passkey | Confirm with another passkey or the password first |
| 22 Step-up verification | An app requires phishing-resistant sign-in; confirm with a passkey without signing in again |
| 23 Approve a payment | CIBA with RFC 9396 payment details in plain words, approved with a passkey |
| 24 Passkey didn't work | Nothing changed; try again or use a password |

<table>
  <tr>
    <td><img src="21-remove-a-passkey.png" width="240" alt="21 remove a passkey"></td>
    <td><img src="22-step-up-verification.png" width="240" alt="22 step up verification"></td>
    <td><img src="23-approve-a-payment-ciba-rar.png" width="240" alt="23 approve a payment ciba rar"></td>
    <td><img src="24-passkey-didn-t-work.png" width="240" alt="24 passkey didn t work"></td>
  </tr>
</table>

## Sessions and identifier-first sign-in (designed)

| Screen | Purpose |
| ------ | ------- |
| 25 Where you're signed in | Sessions with browser, device, last activity, IP and apps; sign out one or all others |
| 26 Sign out everywhere | Lists the apps told to sign out (back-channel logout); optional password change |
| 27 Identifier-first sign-in | Email or login ID first |
| 28 Continue to your organisation | Work email domains go straight to their identity provider |
| 29 New sign-in alert | "Was this you?" on the account page; "No" ends that session |

<table>
  <tr>
    <td><img src="25-account-active-sessions.png" width="240" alt="25 account active sessions"></td>
    <td><img src="26-sign-out-everywhere.png" width="240" alt="26 sign out everywhere"></td>
    <td><img src="27-identifier-first-sign-in.png" width="240" alt="27 identifier first sign in"></td>
    <td><img src="28-continue-to-your-organisation.png" width="240" alt="28 continue to your organisation"></td>
  </tr>
</table>

<table>
  <tr>
    <td><img src="29-new-sign-in-alert.png" width="240" alt="29 new sign in alert"></td>
  </tr>
</table>

## Account recovery (designed)

| Screen | Purpose |
| ------ | ------- |
| 30 Reset your password | Email or login ID |
| 31 Check your email | Same message whether or not the account exists |
| 32 Choose a new password | Length and common-password checks; signs out everywhere else by default |
| 33 Password changed | Confirmation, with a passkey suggestion |

<table>
  <tr>
    <td><img src="30-forgot-password.png" width="240" alt="30 forgot password"></td>
    <td><img src="31-check-your-email.png" width="240" alt="31 check your email"></td>
    <td><img src="32-choose-a-new-password.png" width="240" alt="32 choose a new password"></td>
    <td><img src="33-password-changed.png" width="240" alt="33 password changed"></td>
  </tr>
</table>

## Operator console: clients, signals and security (designed)

| Screen | Purpose |
| ------ | ------- |
| 34 Clients | Registered applications, filterable by how they were registered |
| 35 Client detail | Display details, redirect URIs, scopes, security settings, secret rotation, delete |
| 36 Secret rotated | The new secret is shown once; the old one works for a grace period |
| 37 Shared Signals | Apps receiving CAEP/RISC security events, and what triggers each event |
| 38 Security | Failed sign-ins, locked accounts, passkey adoption, top failing IPs |

<img src="34-console-clients.png" width="720" alt="34 Console: clients">

<img src="35-console-client-detail.png" width="720" alt="35 Console: client detail">

<img src="36-console-secret-rotated.png" width="720" alt="36 Console: secret rotated">

<img src="37-console-shared-signals.png" width="720" alt="37 Console: Shared Signals">

<img src="38-console-security.png" width="720" alt="38 Console: security">
