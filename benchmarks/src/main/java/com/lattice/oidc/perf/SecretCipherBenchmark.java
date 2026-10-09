package com.lattice.oidc.perf;

import com.lattice.oidc.security.SecretCipher;
import com.typesafe.config.ConfigFactory;
import java.util.Map;
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

/** Encrypting an authenticator-app secret (AES-256-GCM) and hashing a recovery code (HMAC-SHA256). */
@Fork(2)
@Warmup(iterations = 5, time = 1, timeUnit = TimeUnit.SECONDS)
@Measurement(iterations = 5, time = 1, timeUnit = TimeUnit.SECONDS)
@State(Scope.Benchmark)
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.MICROSECONDS)
public class SecretCipherBenchmark {

  private SecretCipher cipher;
  private String sealed;

  @Setup
  public void cipher() {
    cipher = new SecretCipher(ConfigFactory.parseMap(Map.of("lattice.second-factor.encryption-key", "benchmark-key")));
    sealed = cipher.encrypt("JBSWY3DPEHPK3PXP");
  }

  @Benchmark
  public String encrypt() {
    return cipher.encrypt("JBSWY3DPEHPK3PXP");
  }

  @Benchmark
  public String decrypt() {
    return cipher.decrypt(sealed);
  }

  @Benchmark
  public String hashRecoveryCode() {
    return cipher.hash("ABCDE12345");
  }
}
