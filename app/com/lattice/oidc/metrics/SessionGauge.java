package com.lattice.oidc.metrics;

import com.lattice.oidc.stores.SessionStore;
import io.micrometer.core.instrument.Gauge;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;

/**
 * {@code lattice_sessions_active}: login sessions within their lifetime, across every server. Read
 * from the session store at each scrape.
 */
@Singleton
public final class SessionGauge {

  @Inject
  public SessionGauge(Metrics metrics, SessionStore sessions) {
    Gauge.builder("lattice.sessions.active", sessions, SessionStore::countActive)
        .description("Login sessions within their lifetime, on every server")
        .register(metrics.registry());
  }
}
