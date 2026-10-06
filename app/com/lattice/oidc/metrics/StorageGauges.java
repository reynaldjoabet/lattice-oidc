package com.lattice.oidc.metrics;

import com.lattice.oidc.security.SecondFactors;
import com.lattice.oidc.stores.EphemeralStore;
import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.MultiGauge;
import io.micrometer.core.instrument.Tags;
import java.util.concurrent.atomic.AtomicLong;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;

/**
 * Gauges read from storage, across every server, refreshed before a scrape (at most every {@link
 * Metrics#REFRESH_INTERVAL}):
 *
 * <ul>
 *   <li>{@code lattice_short_lived_entries{namespace}}: pending sign-ins, device codes, reset links,
 *       ... A namespace that keeps growing points to abuse or a stuck flow.
 *   <li>{@code lattice_second_factor_accounts}: accounts with an authenticator app.
 *   <li>{@code lattice_second_factor_previous_key{kind}}: authenticator secrets and accounts with
 *       recovery codes still under a previous key; a key rotation is finished when both are zero.
 * </ul>
 */
@Singleton
public final class StorageGauges {

  private final AtomicLong accountsWithApp = new AtomicLong();
  private final AtomicLong secretsUnderPreviousKeys = new AtomicLong();
  private final AtomicLong recoveryCodesUnderPreviousKeys = new AtomicLong();

  @Inject
  public StorageGauges(Metrics metrics, EphemeralStore ephemeral, SecondFactors secondFactors) {
    MultiGauge entries =
        MultiGauge.builder("lattice.short.lived.entries")
            .description("Short-lived entries (pending flows, codes, links) by namespace, on every server")
            .register(metrics.registry());
    metrics.beforeScrape(
        () ->
            entries.register(
                ephemeral.counts().entrySet().stream()
                    .map(count -> MultiGauge.Row.of(Tags.of("namespace", count.getKey()), count.getValue()))
                    .toList(),
                true));

    Gauge.builder("lattice.second.factor.accounts", accountsWithApp, AtomicLong::get)
        .description("Accounts with an authenticator app")
        .register(metrics.registry());
    Gauge.builder("lattice.second.factor.previous.key", secretsUnderPreviousKeys, AtomicLong::get)
        .description("Two-step data still under a previous encryption key")
        .tag("kind", "authenticator_secrets")
        .register(metrics.registry());
    Gauge.builder("lattice.second.factor.previous.key", recoveryCodesUnderPreviousKeys, AtomicLong::get)
        .description("Two-step data still under a previous encryption key")
        .tag("kind", "accounts_with_recovery_codes")
        .register(metrics.registry());
    metrics.beforeScrape(
        () -> {
          SecondFactors.Status status = secondFactors.status();
          accountsWithApp.set(status.accountsWithApp());
          secretsUnderPreviousKeys.set(status.secretsUnderPreviousKeys());
          recoveryCodesUnderPreviousKeys.set(status.recoveryCodesUnderPreviousKeys());
        });
  }
}
