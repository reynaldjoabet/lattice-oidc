package com.lattice.oidc.common;

import com.fasterxml.uuid.Generators;
import com.fasterxml.uuid.impl.TimeBasedEpochGenerator;
import com.fasterxml.uuid.impl.TimeBasedEpochRandomGenerator;

/**
 * Identifiers for records and messages: request ids, webhook message ids, consent ids.
 *
 * <p>Both methods return a UUIDv7 (RFC 9562): the first 48 bits are the creation time in
 * milliseconds, so ids sort by creation time, read as a timeline in logs, and append to the end of
 * a database index instead of landing all over it. As text they sort the same way, which suits
 * {@code text} keys.
 *
 * <p>Not for secrets. A UUIDv7 has at most 74 random bits and a guessable timestamp. Session ids,
 * {@code state}, {@code nonce}, PKCE verifiers, device secrets and anything else that grants access
 * to whoever knows it come from {@code UserSessions.randomId()} (256 random bits).
 */
public final class Ids {

  private static final TimeBasedEpochRandomGenerator RANDOM =
      Generators.timeBasedEpochRandomGenerator();
  private static final TimeBasedEpochGenerator SEQUENTIAL = Generators.timeBasedEpochGenerator();

  private Ids() {}

  /**
   * A new UUIDv7 with fresh randomness after the timestamp, as its usual 36-character text. Ids
   * made in the same millisecond are in no particular order among themselves, and one id says
   * nothing about the next. The default: use this unless you need {@link #sequential()}.
   */
  public static String timeOrdered() {
    return RANDOM.generate().toString();
  }

  /**
   * A new UUIDv7 that is strictly greater than the previous one from this JVM, even within a
   * millisecond: the random part of the first id in a millisecond is incremented for each further
   * id. So the next id is predictable from this one, and the order holds only within one process
   * and while the clock does not step back. Use it only where ids made in the same millisecond on
   * one replica must keep their order, for example to page through rows by id.
   */
  public static String sequential() {
    return SEQUENTIAL.generate().toString();
  }
}
