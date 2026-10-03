package com.lattice.oidc.client;

import javax.inject.Inject;
import javax.inject.Singleton;
import org.apache.pekko.actor.ActorSystem;
import play.libs.concurrent.CustomExecutionContext;

/**
 * Executor for blocking Authlete calls (the {@code authlete-dispatcher} pool). Controllers must run
 * Authlete calls here, never on Play's default dispatcher.
 */
@Singleton
public final class AuthleteExecutionContext extends CustomExecutionContext {

  @Inject
  public AuthleteExecutionContext(ActorSystem actorSystem) {
    super(actorSystem, "authlete-dispatcher");
  }
}
