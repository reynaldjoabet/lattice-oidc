import java.util.*;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * A learning model of how Keycloak's token endpoint dispatches on grant_type.
 *
 * Real Keycloak:  TokenEndpoint -> looks up an OAuth2GrantTypeFactory by grant_type (SPI)
 *                 -> factory.create(session) -> new OAuth2GrantType per request -> process(context)
 * This model:     TokenEndpoint -> OAuth2GrantTypeBase.lookup(grant_type) -> shared static instance
 *                 -> process(context)
 *
 * The static instances are safe to share ONLY because they are stateless: every piece of
 * per-request data is passed in through Context instead of being stored in fields
 * (the real OAuth2GrantTypeBase stores it in fields, which is why it creates one per request).
 *
 * Run with:  java GrantsDemo.java
 */
public class GrantsDemo {

    // =====================================================================================
    // In-memory "database" — stands in for Keycloak's realm, user, session and code stores
    // =====================================================================================

    record Client(String id, String secret, Set<String> allowedGrants) {
        boolean isConfidential() { return secret != null; }
    }

    /** A one-time authorization code: the GRANT produced by a browser login + consent. */
    record AuthCode(String user, String clientId, String redirectUri, String scope, long expiresAt) {}

    /** A refresh token: a long-lived GRANT that can be traded for new access tokens. */
    record RefreshGrant(String user, String clientId, String scope) {}

    /** Device flow state: the device polls with deviceCode until a user approves userCode in a browser. */
    static final class DeviceAuthorization {
        final String clientId, userCode, scope;
        String approvedBy; // null until a user approves on another device
        DeviceAuthorization(String clientId, String userCode, String scope) {
            this.clientId = clientId; this.userCode = userCode; this.scope = scope;
        }
    }

    /** What the API would see after validating an access token (like the JWT's claims). */
    record AccessTokenClaims(String sub, String azp, String scope, String aud, long exp) {}

    static final class Store {
        static final Map<String, Client> clients = new HashMap<>();
        static final Map<String, String> users = new HashMap<>();                  // username -> password
        static final Map<String, AuthCode> authCodes = new HashMap<>();
        static final Map<String, RefreshGrant> refreshTokens = new HashMap<>();
        static final Map<String, DeviceAuthorization> deviceCodes = new HashMap<>();
        static final Map<String, AccessTokenClaims> accessTokens = new HashMap<>(); // stands in for JWT validation

        static String newId(String prefix) {
            return prefix + "-" + UUID.randomUUID().toString().substring(0, 8);
        }
    }

    // =====================================================================================
    // Request / response types
    // =====================================================================================

    /** OAuth error -> becomes {"error": ..., "error_description": ...} with HTTP 400/401. */
    static final class OAuthError extends RuntimeException {
        final String error;
        OAuthError(String error, String description) { super(description); this.error = error; }
    }

    /** Everything a grant needs for one request. Mirrors OAuth2GrantType.Context in Keycloak. */
    record Context(Client client, Map<String, String> formParams) {
        String param(String name) { return formParams.get(name); }
        String required(String name) {
            String v = formParams.get(name);
            if (v == null || v.isBlank()) throw new OAuthError("invalid_request", "Missing parameter: " + name);
            return v;
        }
    }

    record TokenResponse(String accessToken, String refreshToken, String scope, int expiresIn) {
        @Override public String toString() {
            return "{ access_token=" + accessToken
                    + (refreshToken != null ? ", refresh_token=" + refreshToken : "")
                    + ", scope=\"" + scope + "\", expires_in=" + expiresIn + " }";
        }
    }

    // =====================================================================================
    // The base class, holding a static instance of every grant type
    // =====================================================================================

    static abstract class OAuth2GrantTypeBase {

        static final int ACCESS_TOKEN_LIFESPAN = 300; // Keycloak's default: 5 minutes

        // ---- the static instances: one per grant_type value ---------------------------
        static final OAuth2GrantTypeBase AUTHORIZATION_CODE = new AuthorizationCodeGrant();
        static final OAuth2GrantTypeBase REFRESH_TOKEN      = new RefreshTokenGrant();
        static final OAuth2GrantTypeBase CLIENT_CREDENTIALS = new ClientCredentialsGrant();
        static final OAuth2GrantTypeBase PASSWORD           = new ResourceOwnerPasswordGrant();
        static final OAuth2GrantTypeBase DEVICE_CODE        = new DeviceCodeGrant();
        static final OAuth2GrantTypeBase TOKEN_EXCHANGE     = new TokenExchangeGrant();

        /** grant_type string -> handler. In Keycloak this lookup is done by the SPI over factories. */
        private static final Map<String, OAuth2GrantTypeBase> BY_TYPE =
                List.of(AUTHORIZATION_CODE, REFRESH_TOKEN, CLIENT_CREDENTIALS, PASSWORD, DEVICE_CODE, TOKEN_EXCHANGE)
                        .stream()
                        .collect(Collectors.toUnmodifiableMap(OAuth2GrantTypeBase::grantType, Function.identity()));

        static Optional<OAuth2GrantTypeBase> lookup(String grantType) {
            return Optional.ofNullable(BY_TYPE.get(grantType));
        }

        // ---- what each grant type must define ------------------------------------------

        /** The value clients send as grant_type=... */
        abstract String grantType();

        /** Validate this request's grant and issue tokens. */
        abstract TokenResponse process(Context ctx);

        /** Same idea as OAuth2GrantType.isConfidentialOnlyGrantType() in Keycloak. */
        boolean isConfidentialOnlyGrantType() { return false; }

        // ---- shared helper: what Keycloak's createTokenResponseBuilder(...) does --------

        protected TokenResponse issueTokens(String user, Client client, String scope, boolean withRefreshToken) {
            String accessToken = Store.newId("at");
            long exp = System.currentTimeMillis() / 1000 + ACCESS_TOKEN_LIFESPAN;
            Store.accessTokens.put(accessToken, new AccessTokenClaims(user, client.id(), scope, "orders-api", exp));

            String refreshToken = null;
            if (withRefreshToken) {
                refreshToken = Store.newId("rt");
                Store.refreshTokens.put(refreshToken, new RefreshGrant(user, client.id(), scope));
            }
            return new TokenResponse(accessToken, refreshToken, scope, ACCESS_TOKEN_LIFESPAN);
        }

        /** Requested scope must be a subset of what the grant allows; scopes can only narrow. */
        protected static String narrowScope(String requested, String granted) {
            if (requested == null) return granted;
            Set<String> allowed = Set.of(granted.split(" "));
            for (String s : requested.split(" ")) {
                if (!allowed.contains(s)) throw new OAuthError("invalid_scope", "Scope not granted: " + s);
            }
            return requested;
        }

        // =================================================================================
        // The grant types. Each one answers: "what proves I'm allowed to get tokens?"
        // =================================================================================

        /** grant = a one-time code obtained after the user logged in (and consented) in a browser. */
        static final class AuthorizationCodeGrant extends OAuth2GrantTypeBase {
            String grantType() { return "authorization_code"; }

            TokenResponse process(Context ctx) {
                String code = ctx.required("code");
                AuthCode stored = Store.authCodes.remove(code); // remove = one-time use
                if (stored == null) throw new OAuthError("invalid_grant", "Code not valid or already used");
                if (stored.expiresAt() < System.currentTimeMillis())
                    throw new OAuthError("invalid_grant", "Code expired");
                if (!stored.clientId().equals(ctx.client().id()))
                    throw new OAuthError("invalid_grant", "Code was issued to another client");
                if (!stored.redirectUri().equals(ctx.param("redirect_uri")))
                    throw new OAuthError("invalid_grant", "redirect_uri mismatch");

                return issueTokens(stored.user(), ctx.client(), stored.scope(), true);
            }
        }

        /** grant = a refresh token from an earlier login. No user interaction. */
        static final class RefreshTokenGrant extends OAuth2GrantTypeBase {
            String grantType() { return "refresh_token"; }

            TokenResponse process(Context ctx) {
                String rt = ctx.required("refresh_token");
                RefreshGrant stored = Store.refreshTokens.remove(rt); // rotation: old one stops working
                if (stored == null) throw new OAuthError("invalid_grant", "Refresh token not valid (revoked or rotated)");
                if (!stored.clientId().equals(ctx.client().id()))
                    throw new OAuthError("invalid_grant", "Refresh token was issued to another client");

                String scope = narrowScope(ctx.param("scope"), stored.scope());
                return issueTokens(stored.user(), ctx.client(), scope, true);
            }
        }

        /** grant = the client's own secret. No user at all; the token is "about" the client itself. */
        static final class ClientCredentialsGrant extends OAuth2GrantTypeBase {
            String grantType() { return "client_credentials"; }
            @Override boolean isConfidentialOnlyGrantType() { return true; }

            TokenResponse process(Context ctx) {
                // The client was already authenticated by the endpoint; that IS the grant.
                String sub = "service-account-" + ctx.client().id();
                // OAuth 2.0 says no refresh token here: the client can just authenticate again.
                return issueTokens(sub, ctx.client(), narrowScope(ctx.param("scope"), "orders:read orders:write"), false);
            }
        }

        /** grant = the user's raw username/password. Deprecated in OAuth 2.1; shown for completeness. */
        static final class ResourceOwnerPasswordGrant extends OAuth2GrantTypeBase {
            String grantType() { return "password"; }

            TokenResponse process(Context ctx) {
                String username = ctx.required("username");
                String password = ctx.required("password");
                if (!password.equals(Store.users.get(username)))
                    throw new OAuthError("invalid_grant", "Invalid user credentials");
                return issueTokens(username, ctx.client(), "openid profile", true);
            }
        }

        /** grant = a device_code that a human approved on another screen (TVs, CLIs). */
        static final class DeviceCodeGrant extends OAuth2GrantTypeBase {
            String grantType() { return "urn:ietf:params:oauth:grant-type:device_code"; }

            TokenResponse process(Context ctx) {
                String deviceCode = ctx.required("device_code");
                DeviceAuthorization da = Store.deviceCodes.get(deviceCode);
                if (da == null || !da.clientId.equals(ctx.client().id()))
                    throw new OAuthError("invalid_grant", "Unknown device_code");
                if (da.approvedBy == null)
                    throw new OAuthError("authorization_pending", "User has not approved yet; keep polling");

                Store.deviceCodes.remove(deviceCode);
                return issueTokens(da.approvedBy, ctx.client(), da.scope, true);
            }
        }

        /** grant = an existing access token (subject_token), traded for one with a different audience/scope. */
        static final class TokenExchangeGrant extends OAuth2GrantTypeBase {
            String grantType() { return "urn:ietf:params:oauth:grant-type:token-exchange"; }
            @Override boolean isConfidentialOnlyGrantType() { return true; }

            TokenResponse process(Context ctx) {
                String subjectToken = ctx.required("subject_token");
                AccessTokenClaims claims = Store.accessTokens.get(subjectToken);
                if (claims == null || claims.exp() < System.currentTimeMillis() / 1000)
                    throw new OAuthError("invalid_grant", "subject_token not valid");

                // The new token is still for the same user (sub), but issued to the calling client
                // and narrowed to what the caller asked for. Exchange never widens permissions.
                String scope = narrowScope(ctx.param("scope"), claims.scope());
                return issueTokens(claims.sub(), ctx.client(), scope, false);
            }
        }
    }

    // =====================================================================================
    // The token endpoint: POST /realms/{realm}/protocol/openid-connect/token
    // =====================================================================================

    static final class TokenEndpoint {

        static String handle(Map<String, String> formParams) {
            try {
                // 1. Authenticate the client (who is calling the token endpoint?)
                Client client = Store.clients.get(formParams.get("client_id"));
                if (client == null) throw new OAuthError("invalid_client", "Unknown client");
                if (client.isConfidential() && !client.secret().equals(formParams.get("client_secret")))
                    throw new OAuthError("invalid_client", "Bad client secret");

                // 2. Pick the grant type handler from grant_type
                String grantType = formParams.get("grant_type");
                OAuth2GrantTypeBase grant = OAuth2GrantTypeBase.lookup(grantType)
                        .orElseThrow(() -> new OAuthError("unsupported_grant_type", "Unknown grant_type: " + grantType));

                // 3. Is THIS client allowed to use THIS grant type? (Keycloak: client "Capability config")
                if (!client.allowedGrants().contains(grantType))
                    throw new OAuthError("unauthorized_client", "Client not allowed to use " + grantType);
                if (grant.isConfidentialOnlyGrantType() && !client.isConfidential())
                    throw new OAuthError("unauthorized_client", "Public clients cannot use " + grantType);

                // 4. Let the grant validate its own credential and issue tokens
                return "200 " + grant.process(new Context(client, formParams));
            } catch (OAuthError e) {
                return "400 { error=" + e.error + ", error_description=\"" + e.getMessage() + "\" }";
            }
        }
    }

    // =====================================================================================
    // Things that happen OUTSIDE the token endpoint, in the browser
    // =====================================================================================

    /** /auth endpoint: user logs in + consents, Keycloak redirects back with ?code=... */
    static String browserLoginAndConsent(String user, String clientId, String redirectUri, String scope) {
        String code = Store.newId("code");
        long expiresAt = System.currentTimeMillis() + 60_000; // codes live ~1 minute
        Store.authCodes.put(code, new AuthCode(user, clientId, redirectUri, scope, expiresAt));
        return code;
    }

    /** Device authorization endpoint: device gets a device_code + a short user_code to show on screen. */
    static String[] startDeviceAuthorization(String clientId, String scope) {
        String deviceCode = Store.newId("dc");
        String userCode = "WDJB-MJHT";
        Store.deviceCodes.put(deviceCode, new DeviceAuthorization(clientId, userCode, scope));
        return new String[]{deviceCode, userCode};
    }

    /** User opens /device on their phone, logs in, types the user_code and approves. */
    static void userApprovesDevice(String userCode, String user) {
        Store.deviceCodes.values().stream()
                .filter(d -> d.userCode.equals(userCode))
                .forEach(d -> d.approvedBy = user);
    }

    // =====================================================================================
    // Demo
    // =====================================================================================

    public static void main(String[] args) {
        Store.users.put("alice", "s3cret");
        Store.clients.put("devdashboard", new Client("devdashboard", "dash-secret",
                Set.of("authorization_code", "refresh_token")));
        Store.clients.put("spa", new Client("spa", null, // public client: no secret
                Set.of("authorization_code", "refresh_token", "client_credentials")));
        Store.clients.put("billing-job", new Client("billing-job", "job-secret",
                Set.of("client_credentials")));
        Store.clients.put("legacy-cli", new Client("legacy-cli", "cli-secret",
                Set.of("password")));
        Store.clients.put("smart-tv", new Client("smart-tv", null,
                Set.of("urn:ietf:params:oauth:grant-type:device_code")));
        Store.clients.put("orders-gateway", new Client("orders-gateway", "gw-secret",
                Set.of("urn:ietf:params:oauth:grant-type:token-exchange")));

        section("1. authorization_code: browser login, then trade the code for tokens");
        String code = browserLoginAndConsent("alice", "devdashboard", "https://dash.example/cb", "openid orders:read");
        System.out.println("browser redirected to https://dash.example/cb?code=" + code);
        Map<String, String> codeRequest = Map.of(
                "grant_type", "authorization_code", "code", code,
                "client_id", "devdashboard", "client_secret", "dash-secret",
                "redirect_uri", "https://dash.example/cb");
        String first = TokenEndpoint.handle(codeRequest);
        System.out.println(first);
        System.out.println("same code again -> " + TokenEndpoint.handle(codeRequest));

        section("2. refresh_token: get a new access token without the user");
        String rt = extract(first, "refresh_token");
        Map<String, String> refreshRequest = Map.of(
                "grant_type", "refresh_token", "refresh_token", rt,
                "client_id", "devdashboard", "client_secret", "dash-secret");
        String refreshed = TokenEndpoint.handle(refreshRequest);
        System.out.println(refreshed);
        System.out.println("old refresh token again (rotated) -> " + TokenEndpoint.handle(refreshRequest));
        System.out.println("ask for MORE scope -> " + TokenEndpoint.handle(Map.of(
                "grant_type", "refresh_token", "refresh_token", extract(refreshed, "refresh_token"),
                "client_id", "devdashboard", "client_secret", "dash-secret",
                "scope", "orders:read orders:write")));

        section("3. client_credentials: a backend job acting as itself, no user");
        System.out.println(TokenEndpoint.handle(Map.of(
                "grant_type", "client_credentials",
                "client_id", "billing-job", "client_secret", "job-secret")));
        System.out.println("public client tries it -> " + TokenEndpoint.handle(Map.of(
                "grant_type", "client_credentials", "client_id", "spa")));

        section("4. password: the app collects the user's password itself (avoid this)");
        System.out.println(TokenEndpoint.handle(Map.of(
                "grant_type", "password", "username", "alice", "password", "s3cret",
                "client_id", "legacy-cli", "client_secret", "cli-secret")));

        section("5. device_code: a TV polls while the user approves on their phone");
        String[] device = startDeviceAuthorization("smart-tv", "openid profile");
        System.out.println("TV shows: go to https://kc.example/device and enter " + device[1]);
        Map<String, String> poll = Map.of(
                "grant_type", "urn:ietf:params:oauth:grant-type:device_code",
                "device_code", device[0], "client_id", "smart-tv");
        System.out.println("TV polls -> " + TokenEndpoint.handle(poll));
        userApprovesDevice(device[1], "alice");
        System.out.println("(alice approves on her phone)");
        System.out.println("TV polls -> " + TokenEndpoint.handle(poll));

        section("6. token-exchange: a gateway trades alice's token for a narrower one");
        String alicesToken = extract(refreshed, "access_token");
        System.out.println(TokenEndpoint.handle(Map.of(
                "grant_type", "urn:ietf:params:oauth:grant-type:token-exchange",
                "subject_token", alicesToken, "scope", "orders:read",
                "client_id", "orders-gateway", "client_secret", "gw-secret")));

        section("7. errors decided by the endpoint before any grant runs");
        System.out.println("unknown grant_type -> " + TokenEndpoint.handle(Map.of(
                "grant_type", "magic", "client_id", "devdashboard", "client_secret", "dash-secret")));
        System.out.println("grant not enabled for client -> " + TokenEndpoint.handle(Map.of(
                "grant_type", "client_credentials", "client_id", "devdashboard", "client_secret", "dash-secret")));
        System.out.println("wrong client secret -> " + TokenEndpoint.handle(Map.of(
                "grant_type", "client_credentials", "client_id", "billing-job", "client_secret", "nope")));
    }

    static void section(String title) { System.out.println("\n=== " + title + " ==="); }

    static String extract(String response, String field) {
        int start = response.indexOf(field + "=") + field.length() + 1;
        int end = response.indexOf(',', start);
        return response.substring(start, end < 0 ? response.indexOf(' ', start) : end).trim();
    }
}
