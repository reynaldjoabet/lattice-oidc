package com.lattice.oidc.controllers;

import com.authlete.common.dto.CredentialOfferCreateRequest;
import com.authlete.common.dto.CredentialOfferCreateResponse;
import com.authlete.common.dto.CredentialOfferInfo;
import com.lattice.oidc.common.Jsons;
import com.lattice.oidc.common.QrCodes;
import com.lattice.oidc.common.LatticeConfig;
import com.lattice.oidc.common.Requests;
import com.lattice.oidc.common.Responses;
import com.lattice.oidc.models.CredentialOfferForm;
import com.lattice.oidc.security.LoginService;
import com.lattice.oidc.security.UserSessions.LoginState;
import com.lattice.oidc.security.UserSessions;
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
 * /api/offer/issue}. The created offer is shown as a QR code to scan with a wallet, with the
 * transaction code and links that open a wallet on the same device (by value, {@code
 * credential_offer}, and by reference, {@code credential_offer_uri}).
 */
public final class CredentialOfferController extends BaseController {


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
    Optional<String> user = sessions.current(request).map(loginState -> loginState.user().displayName());
    CredentialOfferForm form =
        new CredentialOfferForm(DEFAULT_IDS, false, true, true, "", "numeric", "", 0, config.credentialOfferEndpoint(),
            user, Optional.empty(), Optional.empty());
    return page(request, 200, form);
  }

  public CompletionStage<Result> create(Http.Request request) {
    return async(
        () -> {
          Map<String, String[]> f = Requests.form(request);
          CredentialOfferForm form =
              new CredentialOfferForm(
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
          com.lattice.oidc.models.User user;
          if (current.isPresent()) {
            user = current.get().user();
          } else {
            LoginService.Result auth =
                login.authenticate(Requests.first(f, "loginId"), Requests.first(f, "password"));
            auditLogin(request, Requests.first(f, "loginId"), auth);
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
          String offerUriLink = form.endpoint() + "?credential_offer_uri=" + urlEncode(offerUri);
          CredentialOfferForm.Created created =
              new CredentialOfferForm.Created(
                  form.endpoint() + "?credential_offer=" + urlEncode(info.getCredentialOffer()),
                  offerUri,
                  offerUriLink,
                  Jsons.pretty(Jsons.readMap(info.getCredentialOffer())),
                  QrCodes.svg(offerUriLink, "QR code: credential offer for your wallet"),
                  Optional.ofNullable(info.getTxCode()).filter(code -> !code.isEmpty()),
                  java.util.List.of(ids));
          CredentialOfferForm done =
              new CredentialOfferForm(
                  form.credentialConfigurationIds(), form.authorizationCodeGrant(), form.issuerState(),
                  form.preAuthorizedCodeGrant(), form.txCode(), form.txCodeInputMode(),
                  form.txCodeDescription(), form.duration(), form.endpoint(), shown, Optional.empty(),
                  Optional.of(created));
          return sessions.apply(
              Responses.of(
                  200,
                  views.html.oidc.credentialOfferResult.render(done, created, request).body(),
                  Responses.HTML,
                  null),
              request,
              sessionOut);
        });
  }

  private static CredentialOfferForm withError(CredentialOfferForm f, Optional<String> user, String error) {
    return new CredentialOfferForm(
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

  private static String urlEncode(String value) {
    return URLEncoder.encode(value, StandardCharsets.UTF_8);
  }

  private static Result page(Http.Request request, int status, CredentialOfferForm form) {
    return Responses.of(
        status, views.html.oidc.credentialOffer.render(form, request).body(), Responses.HTML, null);
  }
}
