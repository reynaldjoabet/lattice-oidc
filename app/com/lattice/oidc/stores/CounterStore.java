package com.lattice.oidc.stores;

import com.google.inject.ImplementedBy;
import java.time.Duration;

/**
 * Counters within a time window, shared by every server: failed sign-ins, reset emails, device-code
 * guesses. A counter's window starts at its first increment; after the window it starts again at 1.
 */
@ImplementedBy(InMemoryCounterStore.class)
public interface CounterStore {

  /** Adds one and returns the new count within the current window. */
  long increment(String key, Duration window);

  /** The count within the current window (0 if none). */
  long count(String key);

  void reset(String key);

  /** Resets every counter whose key starts with {@code prefix}. */
  void resetPrefix(String prefix);

  /** Counters with a key starting with {@code prefix} whose count is at least {@code minimum}. */
  long countAtLeast(String prefix, long minimum);
}
