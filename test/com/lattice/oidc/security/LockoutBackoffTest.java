package com.lattice.oidc.security;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import com.lattice.oidc.security.LockoutBackoff.State;
import java.time.Duration;
import java.time.Instant;
import org.junit.Test;

public class LockoutBackoffTest {

  private static final Instant T0 = Instant.parse("2026-01-01T00:00:00Z");

  private final LockoutBackoff policy =
      new LockoutBackoff(3, Duration.ofMinutes(1), Duration.ofMinutes(5), Duration.ofHours(1),
          Duration.ofSeconds(1), Duration.ofSeconds(30), 0);

  /** Failures spaced like a person typing: no wait before the threshold, then +1 minute each. */
  @Test
  public void waitsGrowByOneIncrementPerFailureUpToTheMaximum() {
    State state = State.NONE;
    Instant now = T0;
    long[] expectedMinutes = {0, 0, 1, 2, 3, 4, 5, 5, 5};
    for (long minutes : expectedMinutes) {
      state = policy.afterFailure(state, now);
      assertEquals(Duration.ofMinutes(minutes), policy.remaining(state, now));
      now = now.plus(Duration.ofMinutes(10)); // well after any wait, well within the reset
    }
  }

  @Test
  public void lockedUntilTheWaitIsOver() {
    State state = State.NONE;
    for (int i = 0; i < 3; i++) {
      state = policy.afterFailure(state, T0.plusSeconds(10L * i));
    }
    Instant last = T0.plusSeconds(20);
    assertTrue(policy.isLocked(state, last.plusSeconds(59)));
    assertFalse(policy.isLocked(state, last.plusSeconds(60)));
  }

  /** Failures faster than a person types wait even below the threshold. */
  @Test
  public void quickFailuresWaitFromTheSecondAttempt() {
    State state = policy.afterFailure(State.NONE, T0);
    assertFalse(policy.isLocked(state, T0));
    state = policy.afterFailure(state, T0.plusMillis(200));
    assertEquals(Duration.ofSeconds(30), policy.remaining(state, T0.plusMillis(200)));
    assertEquals("a quick failure isn't a temporary lockout", 0, state.temporaryLockouts());
  }

  @Test
  public void failuresExpireAfterTheResetPeriod() {
    State state = policy.afterFailure(State.NONE, T0);
    state = policy.afterFailure(state, T0.plusSeconds(60));
    state = policy.afterFailure(state, T0.plusSeconds(60).plus(Duration.ofHours(2)));
    assertEquals(1, state.failures());
    assertFalse(policy.isLocked(state, state.lastFailure()));
  }

  @Test
  public void successStartsTheCountAgain() {
    State state = policy.afterFailure(policy.afterFailure(State.NONE, T0), T0.plusSeconds(60));
    assertEquals(State.NONE, policy.afterSuccess(state));
  }

  @Test
  public void locksPermanentlyAfterTooManyLockoutsWhenConfigured() {
    LockoutBackoff strict =
        new LockoutBackoff(2, Duration.ofMinutes(1), Duration.ofMinutes(5), Duration.ofHours(1),
            Duration.ZERO, Duration.ZERO, 2);
    State state = State.NONE;
    Instant now = T0;
    for (int i = 0; i < 4; i++) {
      state = strict.afterFailure(state, now);
      now = now.plus(Duration.ofMinutes(10));
    }
    // failures 2 and 3 were temporary lockouts; the 4th is the third lockout
    assertTrue(state.permanentlyLocked());
    assertTrue(strict.isLocked(state, now.plus(Duration.ofDays(365))));
    assertNull(strict.remaining(state, now));
    assertEquals(state, strict.afterSuccess(state));
  }
}
