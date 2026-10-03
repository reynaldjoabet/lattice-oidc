package com.lattice.oidc.controllers;

import com.lattice.oidc.common.Responses;
import play.mvc.Http;
import play.mvc.Result;

/** Simple informational HTML pages. */
public final class Pages {
  private Pages() {}

  public static Result message(Http.Request request, int status, String title, String text) {
    return Responses.of(
        status, views.html.oidc.message.render(title, text, status, request).body(), Responses.HTML, null);
  }
}
