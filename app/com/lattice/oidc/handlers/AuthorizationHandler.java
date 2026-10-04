package com.lattice.oidc.handlers;

import com.authlete.common.api.AuthleteApi;
import com.authlete.common.dto.AuthorizationFailRequest;
import com.authlete.common.dto.AuthorizationFailResponse;
import com.authlete.common.dto.AuthorizationIssueRequest;
import com.authlete.common.dto.AuthorizationIssueResponse;
import com.lattice.oidc.common.LatticeConfig;
import com.lattice.oidc.common.Responses;
import com.lattice.oidc.common.WebException;
import com.lattice.oidc.models.AuthorizationInteraction;
import com.lattice.oidc.models.User;
import com.lattice.oidc.security.PairwiseSubjects;
import com.lattice.oidc.security.UserSessions;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.inject.Inject;
import javax.inject.Provider;
import javax.inject.Singleton;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import play.mvc.Result;

/**
 * Issues or rejects authorization requests through Authlete's /api/auth/authorization/issue and
 * /api/auth/authorization/fail APIs, collecting the claims to embed in the ID token on the way.
 */
@Singleton
public final class AuthorizationHandler {

  private static final Logger LOG = LoggerFactory.getLogger(AuthorizationHandler.class);
  private static final Pattern OPENBANKING_INTENT_ID = Pattern.compile("^([0-9]+):.*$");

  /**
   * The authenticated context in which a ticket is issued.
   *
   * @param user The end-user who granted authorization.
   * @param authTime The time when the end-user was authenticated, in seconds since the Unix epoch.
   * @param sessionId The session ID of the end-user's authentication session. This value is needed for the
   *     {@code sid} claim (back-channel logout) and when "OpenID Connect Native SSO for Mobile Apps
   *     1.0" (a.k.a. "Native SSO") needs to be supported.
   * @param acr The ACR the session was authenticated with (a passkey sign-in or step-up), or null
   *     for a password sign-in.
   */
  public record Grant(User user, long authTime, String sessionId, String acr) {
    public Grant(User user, long authTime, String sessionId) {
      this(user, authTime, sessionId, null);
    }
  }

  private final Provider<AuthleteApi> api;
  private final PairwiseSubjects pairwise;
  private final UserSessions sessions;
  private final LatticeConfig config;

  @Inject
  public AuthorizationHandler(
      Provider<AuthleteApi> api,
      PairwiseSubjects pairwise,
      UserSessions sessions,
      LatticeConfig config) {
    this.api = api;
    this.pairwise = pairwise;
    this.sessions = sessions;
    this.config = config;
  }

  /**
   * The ACR (Authentication Context Class Reference) of the end-user authentication: the first
   * requested ACR that this server's login satisfies.
   *
   * <p>A requested ACR is satisfied by the session's own ACR (a passkey sign-in or step-up) or, for
   * any sign-in, by one listed in {@code lattice.login.satisfied-acrs}. If no ACR is requested, no
   * check is needed. If one of the requested ACRs must be satisfied (essential) and none of them
   * is, the request fails with {@code ACR_NOT_SATISFIED}. If ACR was not requested as essential, it
   * is not necessary to raise an error.
   */
  public String acr(String ticket, String[] requestedAcrs, boolean essential, String sessionAcr) {
    if (requestedAcrs == null || requestedAcrs.length == 0) {
      return null;
    }
    for (String acr : requestedAcrs) {
      if (acr.equals(sessionAcr) || config.satisfiedAcrs().contains(acr)) {
        return acr;
      }
    }
    if (essential) {
      throw new WebException(fail(ticket, AuthorizationFailRequest.Reason.ACR_NOT_SATISFIED));
    }
    return null;
  }

  public Result issue(AuthorizationInteraction interaction, Grant grant) {
    User user = grant.user();
    // The current user is different from the requested subject.
    if (interaction.requestedSubject() != null && !interaction.requestedSubject().equals(user.getSubject())) {
      return fail(interaction.ticket(), AuthorizationFailRequest.Reason.DIFFERENT_SUBJECT);
    }
    String acr = acr(interaction.ticket(), interaction.acrs(), interaction.acrEssential(), grant.acr());

    // Collect claim values. Values of verified claims ("verified_claims", OpenID Connect for
    // Identity Assurance 1.0) are added when the "id_token" property of the "claims" request
    // parameter requests them.
    ClaimsCollector collector = new ClaimsCollector(user);
    Map<String, Object> claims = collector.collect(interaction.claimNames(), interaction.claimLocales());
    claims = customClaims(interaction, claims);
    claims = collector.withVerifiedClaims(claims, interaction.idTokenClaims());
    // Collect values of claims that are indirectly requested by transformed claims.
    // See "OpenID Connect Advanced Syntax for Claims (ASC) 1.0" for details.
    Map<String, Object> claimsForTx =
        collector.collect(interaction.requestedClaimsForTx(), interaction.claimLocales());
    // Values of verified claims that are used to compute values of
    // transformed claims under "verified_claims/claims".
    List<Map<String, Object>> verifiedForTx =
        collector.verifiedClaimsForTx(interaction.idTokenClaims(), interaction.requestedVerifiedClaimsForTx());

    AuthorizationIssueRequest request =
        new AuthorizationIssueRequest()
            .setTicket(interaction.ticket())
            .setSubject(user.getSubject())
            .setAuthTime(grant.authTime())
            .setAcr(acr)
            // The potentially pairwise subject of the end-user.
            .setSub(pairwise.subFor(interaction.subjectType(), interaction.sectorIdentifier(), user.getSubject()))
            .setClaimsForTx(claimsForTx)
            .setVerifiedClaimsForTx(verifiedForTx)
            // The session ID of the user's authentication session (used for the "sid" claim and Native SSO).
            .setSessionId(grant.sessionId());
    if (claims != null && !claims.isEmpty()) {
      request.setClaims(claims);
    }

    // Generate a redirect response containing an authorization code, an access token and/or an ID
    // token. If the original authorization request had response_type=none, no tokens will be
    // contained in the generated response, though.
    AuthorizationIssueResponse response = api.get().authorizationIssue(request);
    String content = response.getResponseContent();
    return switch (response.getAction()) {
      // 302 Found. The client is recorded in the login session so that it can be notified on logout.
      case LOCATION -> {
        sessions.addClient(grant.sessionId(), interaction.clientIdentifier());
        yield Responses.location(content);
      }
      // 200 OK (response_mode=form_post)
      case FORM -> {
        sessions.addClient(grant.sessionId(), interaction.clientIdentifier());
        yield Responses.form(content);
      }
      // 400 Bad Request
      case BAD_REQUEST -> Responses.badRequest(content);
      // 500 Internal Server Error
      case INTERNAL_SERVER_ERROR -> Responses.serverError(content);
      // This never happens.
      default -> throw unknown("/auth/authorization/issue", response.getAction());
    };
  }

  /**
   * Generates an error response to indicate that the authorization request failed, by calling
   * Authlete's /api/auth/authorization/fail API. Depending on the request, the error is returned to
   * the client's redirect URI (302 Found or form_post) or directly to the user agent (400).
   */
  public Result fail(String ticket, AuthorizationFailRequest.Reason reason) {
    AuthorizationFailResponse response =
        api.get().authorizationFail(new AuthorizationFailRequest().setTicket(ticket).setReason(reason));
    String content = response.getResponseContent();
    return switch (response.getAction()) {
      // 302 Found
      case LOCATION -> Responses.location(content);
      // 200 OK (response_mode=form_post)
      case FORM -> Responses.form(content);
      // 400 Bad Request
      case BAD_REQUEST -> Responses.badRequest(content);
      // 500 Internal Server Error
      case INTERNAL_SERVER_ERROR -> Responses.serverError(content);
      // This never happens.
      default -> throw unknown("/auth/authorization/fail", response.getAction());
    };
  }

  /**
   * Claims this server computes rather than reads from the user: {@code txn} (identity assurance
   * transaction id) and {@code openbanking_intent_id} (echoed from the request, bound to the
   * client).
   */
  @SuppressWarnings("unchecked")
  private Map<String, Object> customClaims(AuthorizationInteraction interaction, Map<String, Object> claims) {
    List<String> names = interaction.claimNames() == null ? List.of() : Arrays.asList(interaction.claimNames());
    Map<String, Object> out = claims == null ? new java.util.LinkedHashMap<>() : claims;
    boolean identityAssurance =
        interaction.idTokenClaims() != null && interaction.idTokenClaims().contains("verified_claims");
    if (names.contains("txn") || identityAssurance) {
      out.put("txn", UUID.randomUUID().toString());
    }
    // openbanking_intent_id: its value is taken from the "id_token" property of the "claims" request
    // parameter. When it has the form "{clientId}:...", it must belong to the requesting client.
    if (names.contains("openbanking_intent_id")) {
      Object entry =
          interaction.idTokenClaims() == null
              ? null
              : com.lattice.oidc.common.Jsons.readMap(interaction.idTokenClaims()).get("openbanking_intent_id");
      Object value = entry instanceof Map<?, ?> m ? ((Map<String, Object>) m).get("value") : null;
      if (!(value instanceof String intentId)) {
        throw invalidRequest("The value of 'openbanking_intent_id' is not available.");
      }
      Matcher matcher = OPENBANKING_INTENT_ID.matcher(intentId);
      if (matcher.matches() && !matcher.group(1).equals(String.valueOf(interaction.clientId()))) {
        throw invalidRequest("The 'openbanking_intent_id' is not for the client.");
      }
      out.put("openbanking_intent_id", intentId);
    }
    return out.isEmpty() ? null : out;
  }

  private static WebException invalidRequest(String description) {
    return new WebException(Responses.badRequest(Responses.error("invalid_request", description)));
  }

  private static WebException unknown(String path, Object action) {
    LOG.error("Authlete {} returned an unknown action: {}", path, action);
    return new WebException(Responses.serverError(Responses.error("server_error", null)));
  }
}
