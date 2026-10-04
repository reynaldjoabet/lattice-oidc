package com.lattice.oidc.controllers;

import com.lattice.oidc.common.Responses;
import com.lattice.oidc.models.AuthorizationPage;
import play.mvc.Http;
import play.mvc.Result;

/** Shared HTML pages: authorization steps and short outcome messages. */
public final class Pages {
  private Pages() {}

  /** An outcome page; failures (4xx/5xx) get a warning look and a reference for support. */
  public static Result message(Http.Request request, int status, String title, String text) {
    return message(request, status, title, text, status >= 400 ? "warning" : "info");
  }

  /** A success page (device connected, sign-in approved, ...). */
  public static Result success(Http.Request request, String title, String text) {
    return message(request, 200, title, text, "success");
  }

  private static Result message(Http.Request request, int status, String title, String text, String tone) {
    return Responses.of(
        status,
        views.html.oidc.message.render(title, text, status, tone, request).body(),
        Responses.HTML,
        null);
  }

  /** The sign-in step (email first, then password) or, once signed in, the consent page. */
  public static Result authorization(Http.Request request, AuthorizationPage page, int status) {
    String body =
        page.loggedInAs().isPresent()
            ? views.html.oidc.authorization.render(page, request).body()
            : page.identified()
                ? views.html.oidc.signInPassword.render(page, request).body()
                : views.html.oidc.signIn.render(page, request).body();
    return Responses.of(status, body, Responses.HTML, null);
  }
}
