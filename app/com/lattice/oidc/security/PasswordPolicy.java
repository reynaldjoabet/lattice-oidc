package com.lattice.oidc.security;

import com.lattice.oidc.models.User;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * Rules for new passwords (NIST SP 800-63B): at least 12 characters, not a commonly used password,
 * and not the current one. No composition rules.
 */
public final class PasswordPolicy {

  public static final int MINIMUM_LENGTH = 12;

  /** A short list of the most common passwords of 12 or more characters. */
  private static final Set<String> COMMON =
      Set.of(
          "123456789012", "1234567890123", "12345678901234", "123456789abc", "1q2w3e4r5t6y",
          "qwertyuiop12", "qwertyuiopas", "qwerty123456", "password1234", "password12345",
          "password123!", "passwordpassword", "iloveyou1234", "abcdefghijkl", "abc123456789",
          "aaaaaaaaaaaa", "111111111111", "000000000000", "letmein12345", "welcome12345",
          "changeme1234", "administrator", "football1234", "baseball1234", "trustno1trustno1",
          "qazwsxedcrfv", "1qaz2wsx3edc", "zaq12wsxcde3", "princess1234", "sunshine1234");

  private PasswordPolicy() {}

  /** What's wrong with {@code password} for {@code user}; empty when it is acceptable. */
  public static List<String> problems(String password, User user) {
    List<String> problems = new ArrayList<>();
    if (password == null || password.codePointCount(0, password.length()) < MINIMUM_LENGTH) {
      problems.add("Use at least " + MINIMUM_LENGTH + " characters.");
      return problems;
    }
    String lower = password.toLowerCase(Locale.ROOT);
    if (COMMON.contains(lower)
        || (user.loginId() != null && lower.contains(user.loginId().toLowerCase(Locale.ROOT)) && lower.length() < user.loginId().length() + 6)) {
      problems.add("Choose a password that is less common.");
    }
    if (user.passwordHash() != null && PasswordHasher.check(password, user.passwordHash())) {
      problems.add("Choose a password different from your current one.");
    }
    return problems;
  }

  /** The Argon2 hash to store. */
  public static String hash(String password) {
    return PasswordHasher.hash(password);
  }
}
