package com.lattice.oidc.endpoints;

import com.authlete.common.dto.AttestationChallengeRequest;
import com.authlete.common.dto.AttestationChallengeResponse;
import com.lattice.oidc.http.AuthleteController;
import com.lattice.oidc.http.Responses;
import java.util.concurrent.CompletionStage;
import play.mvc.Result;

/**
 * An implementation of the challenge endpoint defined in OAuth 2.0 Attestation-Based Client
 * Authentication: {@code POST /api/challenge}.
 *
 * @see <a href="https://datatracker.ietf.org/doc/draft-ietf-oauth-attestation-based-client-auth/">OAuth 2.0 Attestation-Based Client Authentication</a>
 */
public final class AttestationController extends AuthleteController {

  /**
   * The challenge endpoint.
   *
   * <p>From OAuth 2.0 Attestation-Based Client Authentication: "A request for a Challenge is made by
   * sending an HTTP POST request to the URL provided in the challenge_endpoint of the Authorization
   * Server metadata."
   */
  public CompletionStage<Result> challenge() {
    return async(
        () -> {
          AttestationChallengeResponse r =
              api().attestationChallenge(new AttestationChallengeRequest().setPretty(false));
          return switch (r.getAction()) {
            case OK -> Responses.ok(r.getResponseContent());
            case INTERNAL_SERVER_ERROR -> Responses.serverError(r.getResponseContent());
            default -> throw unknownAction("/attestation/challenge", r.getAction());
          };
        });
  }
}
