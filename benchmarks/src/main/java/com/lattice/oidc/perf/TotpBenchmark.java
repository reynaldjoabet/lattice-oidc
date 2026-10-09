package com.lattice.oidc.perf;

import com.lattice.oidc.security.Totp;
import com.lattice.oidc.security.TotpCodes;
import java.time.Instant;
import java.util.OptionalLong;
import java.util.concurrent.TimeUnit;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Measurement;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.Warmup;

/** Checking a 6-digit authenticator code: HMAC-SHA1 over the previous, current and next step. */
@Fork(2)
@Warmup(iterations = 5, time = 1, timeUnit = TimeUnit.SECONDS)
@Measurement(iterations = 5, time = 1, timeUnit = TimeUnit.SECONDS)
@State(Scope.Benchmark)
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.MICROSECONDS)
public class TotpBenchmark {

  private String secret;
  private Instant now;
  private String rightCode;

  @Setup
  public void secret() {
    secret = Totp.newSecret();
    now = Instant.now();
    rightCode = TotpCodes.at(secret, Totp.step(now));
  }

  @Benchmark
  public OptionalLong verifyRightCode() {
    return Totp.verify(secret, rightCode, now);
  }

  /** Tries all three steps before refusing, the most work a check does. */
  @Benchmark
  public OptionalLong verifyWrongCode() {
    return Totp.verify(secret, "000000", now);
  }
}
