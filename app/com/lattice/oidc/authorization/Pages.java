package com.lattice.oidc.authorization;

import com.lattice.oidc.http.Responses;
import play.mvc.Http;
import play.mvc.Result;

/** Simple informational HTML pages. */
public final class Pages {
  private Pages() {}

  public static Result message(Http.Request request, int status, String title, String text) {
    return Responses.of(
        status, views.html.oidc.message.render(title, text, request).body(), Responses.HTML, null);
  }
}
