package com.lattice.oidc.controllers;

import com.lattice.oidc.common.Responses;
import com.lattice.oidc.security.UserSessions;
import java.util.Optional;
import javax.inject.Inject;
import play.mvc.Controller;
import play.mvc.Http;
import play.mvc.Result;

/** Start page of the sign-in service ({@code GET /}). */
public final class HomeController extends Controller {

  private final UserSessions sessions;

  @Inject
  public HomeController(UserSessions sessions) {
    this.sessions = sessions;
  }

  public Result index(Http.Request request) {
    Optional<String> user = sessions.current(request).map(s -> s.user().displayName());
    return Responses.of(
        200, views.html.oidc.home.render(user, request).body(), Responses.HTML, null);
  }
}
