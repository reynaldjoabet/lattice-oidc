package com.lattice.oidc.client.resilience;

/**
 * Notified of what the resilience layer did for a call, for metrics. {@code event} is one of
 * {@code cache_hit} (answered from the cache), {@code stale} (Authlete failed; an expired cached
 * answer was served), {@code retry} (a failed call is tried again) and {@code rejected} (a circuit
 * breaker is open and there was nothing cached to serve).
 */
@FunctionalInterface
public interface ResilienceListener {

  ResilienceListener NONE = (method, event) -> {};

  void event(String method, String event);
}
