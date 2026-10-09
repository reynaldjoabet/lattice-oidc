package com.lattice.oidc.perf;

import com.password4j.Password;
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

/**
 * The cost of one password check (Argon2, as in {@code LoginService}): the dominant CPU cost of a
 * sign-in, and what makes the sign-in endpoint the one to size servers for. A wrong password costs
 * the same as a right one (and so does an unknown account, which checks a dummy hash), so response
 * time doesn't reveal which accounts exist.
 *
 * <p>Run with several threads (for example {@code -t 4}) to see how it scales over the cores.
 */
@Fork(1)
@Warmup(iterations = 3, time = 2, timeUnit = TimeUnit.SECONDS)
@Measurement(iterations = 5, time = 2, timeUnit = TimeUnit.SECONDS)
@State(Scope.Benchmark)
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.MILLISECONDS)
public class PasswordHashingBenchmark {

  private String hash;

  @Setup
  public void hash() {
    hash = Password.hash("correct horse battery staple").addRandomSalt().withArgon2().getResult();
  }

  @Benchmark
  public boolean verifyCorrectPassword() {
    return Password.check("correct horse battery staple", hash).withArgon2();
  }

  @Benchmark
  public boolean verifyWrongPassword() {
    return Password.check("wrong password", hash).withArgon2();
  }

  @Benchmark
  public String hashNewPassword() {
    return Password.hash("correct horse battery staple").addRandomSalt().withArgon2().getResult();
  }
}
