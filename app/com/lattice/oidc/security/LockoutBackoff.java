package com.lattice.oidc.security;

import java.time.Duration;
import java.time.Instant;

/**
 * An incremental lockout policy: the more failed sign-ins in a row, the longer the wait before the
 * next attempt is allowed, up to a limit; optionally a permanent lock after repeated lockouts. A
 * pure function of the previous {@link State} and the time, so it can be stored anywhere (a row, a
 * cache entry) and tested without a clock.
 *
 * <p>Compared with a fixed rule ("5 failures in 15 minutes locks for 15 minutes"):
 *
 * <ul>
 *   <li><b>Growing waits.</b> A person who mistypes a few times waits seconds; a script guessing
 *       for hours is slowed to one guess per {@code maxWait}. With {@code waitIncrement} 60 s and
 *       {@code failureFactor} 5, the 5th failure waits 1 minute, the 6th 2, the 7th 3, and so on.
 *   <li><b>A quick-failure check.</b> Failures closer together than {@code quickFailureWindow} (no
 *       person types that fast) wait {@code quickFailureWait} even below the threshold, which slows
 *       a script from the very first guesses.
 *   <li><b>Failures expire.</b> A failure more than {@code failureReset} after the previous one
 *       starts the count again, so occasional typos over weeks never add up to a lockout.
 *   <li><b>Optional permanent lock</b> after {@code maxTemporaryLockouts} lockouts (0 = never), for
 *       deployments that want an administrator to unlock the account.
 * </ul>
 *
 * <p>Whose failures to count is the caller's choice, and it matters: keyed on the account alone, an
 * attacker can keep anyone locked out by failing on purpose. Keyed on account and IP address (as
 * Lattice's sign-in counts), the real user signing in from elsewhere is unaffected.
 *
 * @param failureFactor failures in a row before waits start (at least 1)
 * @param waitIncrement how much longer each further failure waits
 * @param maxWait the longest wait
 * @param failureReset a failure this long after the previous one starts the count again
 * @param quickFailureWindow failures closer together than this count as scripted
 * @param quickFailureWait the wait after a quick failure below the threshold
 * @param maxTemporaryLockouts lockouts before the account locks permanently; 0 for never
 */
public record LockoutBackoff(
    int failureFactor,
    Duration waitIncrement,
    Duration maxWait,
    Duration failureReset,
    Duration quickFailureWindow,
    Duration quickFailureWait,
    int maxTemporaryLockouts) {

  /** The defaults: 5 failures, then +1 minute per failure up to 15 minutes; never permanent. */
  public static final LockoutBackoff DEFAULT =
      new LockoutBackoff(5, Duration.ofMinutes(1), Duration.ofMinutes(15), Duration.ofHours(12),
          Duration.ofSeconds(1), Duration.ofMinutes(1), 0);

  public LockoutBackoff {
    if (failureFactor < 1 || maxTemporaryLockouts < 0) {
      throw new IllegalArgumentException("failureFactor must be at least 1 and maxTemporaryLockouts not negative");
    }
    for (Duration duration : new Duration[] {waitIncrement, maxWait, failureReset, quickFailureWindow, quickFailureWait}) {
      if (duration == null || duration.isNegative()) {
        throw new IllegalArgumentException("Durations must be set and not negative");
      }
    }
  }

  /**
   * The failure record of one account (or account and IP address).
   *
   * @param failures failures in a row since the count last started
   * @param temporaryLockouts lockouts since the count last started
   * @param lastFailure when the latest failure happened; null if none
   * @param lockedUntil no attempt is allowed before this; null if not locked
   * @param permanentlyLocked locked until an administrator unlocks it
   */
  public record State(int failures, int temporaryLockouts, Instant lastFailure, Instant lockedUntil, boolean permanentlyLocked) {
    public static final State NONE = new State(0, 0, null, null, false);
  }

  /** Whether an attempt at {@code now} must be refused without checking the password. */
  public boolean isLocked(State state, Instant now) {
    return state.permanentlyLocked() || (state.lockedUntil() != null && now.isBefore(state.lockedUntil()));
  }

  /** How long until an attempt is allowed again; zero if it is now, null if only an administrator can unlock. */
  public Duration remaining(State state, Instant now) {
    if (state.permanentlyLocked()) {
      return null;
    }
    return isLocked(state, now) ? Duration.between(now, state.lockedUntil()) : Duration.ZERO;
  }

  /** The record after a failed attempt at {@code now}. */
  public State afterFailure(State state, Instant now) {
    if (state.permanentlyLocked()) {
      return state;
    }
    Instant last = state.lastFailure();
    Duration sinceLast = last == null ? null : Duration.between(last, now);
    boolean expired = sinceLast != null && sinceLast.compareTo(failureReset) > 0;
    int failures = (expired ? 0 : state.failures()) + 1;
    int lockouts = expired ? 0 : state.temporaryLockouts();

    Duration wait = failures < failureFactor ? Duration.ZERO : waitIncrement.multipliedBy(1L + failures - failureFactor);
    boolean quick = false;
    if (wait.isZero() && sinceLast != null && !expired && sinceLast.compareTo(quickFailureWindow) < 0) {
      wait = quickFailureWait;
      quick = true;
    }
    if (wait.isZero()) {
      return new State(failures, lockouts, now, state.lockedUntil(), false);
    }
    if (wait.compareTo(maxWait) > 0) {
      wait = maxWait;
    }
    if (!quick) {
      lockouts++;
    }
    boolean permanent = maxTemporaryLockouts > 0 && lockouts > maxTemporaryLockouts;
    return new State(failures, lockouts, now, now.plus(wait), permanent);
  }

  /** The record after a successful sign-in: the count starts again. */
  public State afterSuccess(State state) {
    return state.permanentlyLocked() ? state : State.NONE;
  }
}
