package com.lattice.oidc.models;

import java.util.Optional;

/**
 * A validated RP-initiated logout request: {@code client_id} is resolved from the {@code
 * id_token_hint} when absent, and {@code post_logout_redirect_uri} is registered for that client.
 */
public record LogoutRequest(
    Optional<String> idTokenHint,
    Optional<String> clientId,
    Optional<String> postLogoutRedirectUri,
    Optional<String> state,
    Optional<String> hintSubject,
    Optional<String> hintSessionId) {}
