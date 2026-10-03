package com.lattice.oidc.vci;

import com.authlete.common.dto.CredentialOfferCreateRequest;
import com.authlete.common.dto.CredentialOfferCreateResponse;
import com.authlete.common.dto.CredentialOfferInfo;
import com.lattice.oidc.config.LatticeConfig;
import com.lattice.oidc.http.AuthleteController;
import com.lattice.oidc.http.Jsons;
import com.lattice.oidc.http.Requests;
import com.lattice.oidc.http.Responses;
import com.lattice.oidc.session.UserSessions;
import com.lattice.oidc.session.UserSessions.LoginState;
import com.lattice.oidc.user.LoginService;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletionStage;
import javax.inject.Inject;
import play.mvc.Http;
import play.mvc.Result;

/**
 * A page for an authenticated end-user to create a credential offer for themselves: {@code GET|POST
 * /api/offer/issue}. The created offer is shown both by value ({@code credential_offer}) and by
 * reference ({@code credential_offer_uri}), as links for a wallet.
 */
public final class CredentialOfferController extends AuthleteController {

  /** Form values and, after creation, the resulting offer. */
  public record OfferForm(
      String credentialConfigurationIds,
      boolean authorizationCodeGrant,
      boolean issuerState,
      boolean preAuthorizedCodeGrant,
      String txCode,
      String txCodeInputMode,
      String txCodeDescription,
      int duration,
      String endpoint,
      Optional<String> user,
      Optional<String> error,
      Optional<Created> created) {}

  public record Created(String offerLink, String offerUri, String offerUriLink, String offerJson) {}

  private static final String DEFAULT_IDS =
      "[\"DigitalCredential\", \"IdentityCredential\", \"org.iso.18013.5.1.mDL\"]";

  private final UserSessions sessions;
  private final LoginService login;
  private final LatticeConfig config;

  @Inject
  public CredentialOfferController(UserSessions sessions, LoginService login, LatticeConfig config) {
    this.sessions = sessions;
    this.login = login;
    this.config = config;
  }

  public Result form(Http.Request request) {
    Optional<String> user = sessions.current(request).map(s -> s.user().displayName());
    OfferForm form =
        new OfferForm(DEFAULT_IDS, false, true, true, "", "numeric", "", 0, config.credentialOfferEndpoint(),
            user, Optional.empty(), Optional.empty());
    return page(request, 200, form);
  }

  public CompletionStage<Result> create(Http.Request request) {
    return async(
        () -> {
          Map<String, String[]> f = Requests.form(request);
          OfferForm form =
              new OfferForm(
                  value(f, "credentialConfigurationIds", DEFAULT_IDS),
                  f.containsKey("authorizationCodeGrantIncluded"),
                  f.containsKey("issuerStateIncluded"),
                  f.containsKey("preAuthorizedCodeGrantIncluded"),
                  value(f, "txCode", ""),
                  value(f, "txCodeInputMode", "numeric"),
                  value(f, "txCodeDescription", ""),
                  parseDuration(value(f, "duration", "0")),
                  value(f, "credentialOfferEndpoint", config.credentialOfferEndpoint()),
                  Optional.empty(),
                  Optional.empty(),
                  Optional.empty());

          Map<String, String> sessionOut = new HashMap<>();
          Optional<LoginState> current = sessions.current(request);
          com.lattice.oidc.user.User user;
          if (current.isPresent()) {
            user = current.get().user();
          } else {
            LoginService.Result auth =
                login.authenticate(Requests.first(f, "loginId"), Requests.first(f, "password"));
            if (auth.outcome() != LoginService.Outcome.SUCCESS) {
              return page(request, 401, withError(form, Optional.empty(), "Invalid login ID or password."));
            }
            user = auth.user().get();
            sessions.login(user, System.currentTimeMillis() / 1000L, null, sessionOut);
          }
          Optional<String> shown = Optional.of(user.displayName());

          String[] ids;
          try {
            ids = Jsons.readList(form.credentialConfigurationIds()).stream().map(String.class::cast).toArray(String[]::new);
          } catch (RuntimeException e) {
            return page(request, 400, withError(form, shown, "Credential configuration IDs must be a JSON array of strings."));
          }
          if (form.duration() < 0) {
            return page(request, 400, withError(form, shown, "Duration must be a non-negative number."));
          }

          CredentialOfferCreateResponse r =
              api()
                  .credentialOfferCreate(
                      new CredentialOfferCreateRequest()
                          .setCredentialConfigurationIds(ids)
                          .setAuthorizationCodeGrantIncluded(form.authorizationCodeGrant())
                          .setIssuerStateIncluded(form.issuerState())
                          .setPreAuthorizedCodeGrantIncluded(form.preAuthorizedCodeGrant())
                          .setTxCode(form.txCode().isEmpty() ? null : form.txCode())
                          .setTxCodeInputMode(form.txCodeInputMode())
                          .setTxCodeDescription(form.txCodeDescription().isEmpty() ? null : form.txCodeDescription())
                          .setDuration(form.duration())
                          .setSubject(user.getSubject()));
          if (r.getAction() != CredentialOfferCreateResponse.Action.CREATED) {
            return page(request, 400, withError(form, shown, "The offer could not be created: " + r.getResultMessage()));
          }
          CredentialOfferInfo info = r.getInfo();
          String offerUri = info.getCredentialIssuer() + "/api/offer/" + info.getIdentifier();
          Created created =
              new Created(
                  form.endpoint() + "?credential_offer=" + enc(info.getCredentialOffer()),
                  offerUri,
                  form.endpoint() + "?credential_offer_uri=" + enc(offerUri),
                  Jsons.pretty(Jsons.readMap(info.getCredentialOffer())));
          OfferForm done =
              new OfferForm(
                  form.credentialConfigurationIds(), form.authorizationCodeGrant(), form.issuerState(),
                  form.preAuthorizedCodeGrant(), form.txCode(), form.txCodeInputMode(),
                  form.txCodeDescription(), form.duration(), form.endpoint(), shown, Optional.empty(),
                  Optional.of(created));
          return sessions.apply(page(request, 200, done), request, sessionOut);
        });
  }

  private static OfferForm withError(OfferForm f, Optional<String> user, String error) {
    return new OfferForm(
        f.credentialConfigurationIds(), f.authorizationCodeGrant(), f.issuerState(),
        f.preAuthorizedCodeGrant(), f.txCode(), f.txCodeInputMode(), f.txCodeDescription(),
        f.duration(), f.endpoint(), user, Optional.of(error), Optional.empty());
  }

  private static String value(Map<String, String[]> f, String name, String fallback) {
    String v = Requests.first(f, name);
    return v == null ? fallback : v;
  }

  private static int parseDuration(String value) {
    try {
      return Integer.parseInt(value.trim());
    } catch (NumberFormatException e) {
      return -1;
    }
  }

  private static String enc(String value) {
    return URLEncoder.encode(value, StandardCharsets.UTF_8);
  }

  private static Result page(Http.Request request, int status, OfferForm form) {
    return Responses.of(
        status, views.html.oidc.credentialOffer.render(form, request).body(), Responses.HTML, null);
  }
}
