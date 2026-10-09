
package com.lattice.oidc.client.resilience;


import java.util.concurrent.ConcurrentHashMap;


/**
 * Lazily creates and holds one {@link AuthleteCircuitBreaker} per Authlete API method.
 *
 * <p>
 * Keeping breakers per method isolates failures: a breaker that has tripped for
 * one endpoint (e.g. client management) does not affect another, higher-priority
 * endpoint (e.g. introspection).
 * </p>
 */
class AuthleteCircuitBreakerRegistry
{
    private final ConcurrentHashMap<String, AuthleteCircuitBreaker> breakers =
            new ConcurrentHashMap<String, AuthleteCircuitBreaker>();

    private final int  failureThreshold;
    private final long windowMillis;
    private final long openMillis;
    private final int  halfOpenTrials;


    AuthleteCircuitBreakerRegistry(ResilienceConfig config)
    {
        this.failureThreshold = config.getBreakerFailureThreshold();
        this.windowMillis     = config.getBreakerWindowMillis();
        this.openMillis       = config.getBreakerOpenMillis();
        this.halfOpenTrials   = config.getBreakerHalfOpenTrials();
    }


    /**
     * Get the breaker for the given method name, creating it on first use.
     */
    AuthleteCircuitBreaker forMethod(String methodName)
    {
        AuthleteCircuitBreaker existing = breakers.get(methodName);

        if (existing != null)
        {
            return existing;
        }

        AuthleteCircuitBreaker created =
                new AuthleteCircuitBreaker(failureThreshold, windowMillis, openMillis, halfOpenTrials);

        AuthleteCircuitBreaker previous = breakers.putIfAbsent(methodName, created);

        return (previous != null) ? previous : created;
    }


    /**
     * How many breakers are open (for the metric). A breaker past its
     * open period still reports OPEN until the next call moves it to HALF_OPEN.
     */
    int openCount()
    {
        int open = 0;

        for (AuthleteCircuitBreaker breaker : breakers.values())
        {
            if (breaker.getState() == AuthleteCircuitBreaker.State.OPEN)
            {
                open++;
            }
        }

        return open;
    }
}
