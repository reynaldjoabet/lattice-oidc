# Design and screens

Designs for every end-user and operator screen of Lattice. The screenshots below are rendered from the design canvas; the editable source lives in the canvas ([Lattice OIDC screens](https://claude.ai/artifact/CRds8ufKFuZjJGn3n1aqBB), private until shared).

**Status** in each table says whether the screen exists in the app today:

- **Built**: a Twirl template exists; the design refines it.
- **New**: needs a template and, usually, backend work.

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

| Screen | Purpose | Flow | Status |
| ------ | ------- | ---- | ------ |
| 01 Sign in | Password sign-in plus "continue with" upstream providers | Authorization code (`/api/authorization`), identity brokering | Built, as part of `authorization.scala.html` |
| 02 Sign in: locked | Shown after `lattice.login.max-failures` wrong passwords | Same | Built (error state) |
| 03 Consent | What the app gets, in plain language; switch account | Authorization decision (`/api/authorization/decision`) | Built; the design splits sign-in and consent into two steps |
| 04 Link accounts | A brokered sign-in matches an existing account's email; confirm with the password | Identity brokering callback | **New** |

<table>
  <tr>
    <td><img src="01-sign-in.png" width="240" alt="01 Sign in"></td>
    <td><img src="02-sign-in-locked.png" width="240" alt="02 Sign in: locked"></td>
    <td><img src="03-consent.png" width="240" alt="03 Consent"></td>
    <td><img src="04-link-accounts.png" width="240" alt="04 Link accounts"></td>
  </tr>
</table>

## Devices and decoupled sign-in

| Screen | Purpose | Flow | Status |
| ------ | ------- | ---- | ------ |
| 05 Enter code | Type the code a TV or console shows | Device flow (RFC 8628), `/api/device/verification` | Built (`deviceVerification.scala.html`) |
| 06 Confirm device | Match the code, see what the device gets | `/api/device/complete` | Built (`deviceAuthorization.scala.html`) |
| 07 Device connected | Success, with a pointer to removing the device | Same | Built (generic message page) |
| 08 Approve sign-in | Approve a sign-in started on another device; binding message and countdown | CIBA, completed through `CibaHandler.callback` | **New**: replaces the external CIBA simulator |

<table>
  <tr>
    <td><img src="05-device-enter-code.png" width="240" alt="05 Enter code"></td>
    <td><img src="06-device-confirm.png" width="240" alt="06 Confirm device"></td>
    <td><img src="07-device-connected.png" width="240" alt="07 Device connected"></td>
    <td><img src="08-approve-sign-in-ciba.png" width="240" alt="08 Approve sign-in"></td>
  </tr>
</table>

## Session and account

| Screen | Purpose | Flow | Status |
| ------ | ------- | ---- | ------ |
| 09 Sign out? | Confirm when the logout request has no matching `id_token_hint`; lists the apps that will be signed out | RP-initiated logout (`/api/logout`) | Built (`logoutConfirm.scala.html`) |
| 10 Signed out | Confirmation, with a return link to the app | Same, with back-channel logout | Built (generic message page) |
| 11 Account | Connected apps, devices and sign-in methods, each removable | Grant management, session clients | **New** |
| 12 Request expired | Expired or foreign-browser request, with a request ID for support | Any browser flow | Built (`error.scala.html` / message page) |

<table>
  <tr>
    <td><img src="09-sign-out.png" width="240" alt="09 Sign out?"></td>
    <td><img src="10-signed-out.png" width="240" alt="10 Signed out"></td>
    <td><img src="11-account-connected-apps.png" width="240" alt="11 Account"></td>
    <td><img src="12-error-request-expired.png" width="240" alt="12 Request expired"></td>
  </tr>
</table>

## Wallets and open banking

| Screen | Purpose | Flow | Status |
| ------ | ------- | ---- | ------ |
| 13 Credential offer | Scan a QR code or open the wallet; shows the transaction code | OpenID4VCI credential offer | **New** end-user view (today's `credentialOffer.scala.html` is a developer tool) |
| 14 Open banking consent | Choose the account, see each permission and the expiry | Open Banking Brasil consents | **New** as a dedicated screen |

<table>
  <tr>
    <td><img src="13-credential-offer-wallet.png" width="240" alt="13 Credential offer"></td>
    <td><img src="14-open-banking-consent.png" width="240" alt="14 Open banking consent"></td>
  </tr>
</table>

## Operator console

| Screen | Purpose | Status |
| ------ | ------- | ------ |
| 15 Overview | Authlete status, active sessions, identity providers, locked logins, the six caches (sizes and hit rates from `record-stats`) and recent audit events | **New**: must sit behind real admin authentication before it ships |

<img src="15-operator-console.png" width="720" alt="15 Operator console">
