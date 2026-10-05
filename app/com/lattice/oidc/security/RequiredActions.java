package com.lattice.oidc.security;

import com.lattice.oidc.models.User;
import com.lattice.oidc.stores.PasskeyStore;
import com.lattice.oidc.stores.UserStore;
import com.typesafe.config.Config;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.inject.Inject;
import javax.inject.Singleton;

/**
 * Required actions: steps a signed-in user must complete before using apps or their account.
 * Each is pending while its condition holds, so it disappears as soon as the user meets it,
 * however they meet it:
 *
 * <ul>
 *   <li>{@code VERIFY_EMAIL}: the email isn't verified, and {@code
 *       lattice.required-actions.verify-email} is on or the account is flagged.
 *   <li>{@code TERMS_AND_CONDITIONS}: {@code lattice.required-actions.terms-version} is set and the
 *       user hasn't accepted that version.
 *   <li>{@code UPDATE_PASSWORD}: the account is flagged (for example after an operator set a
 *       temporary password); cleared when the user chooses a new one.
 *   <li>{@code CONFIGURE_TOTP}: the account is flagged and has no authenticator app; or {@code
 *       lattice.second-factor.required} is on and the account has neither an authenticator app nor a
 *       passkey.
 *   <li>{@code CONFIGURE_PASSKEY}: the account is flagged and has no passkey.
 * </ul>
 *
 * Operators flag an account by listing action names in its {@code requiredActions} attribute.
 */
@Singleton
public final class RequiredActions {

  public enum Action {
    VERIFY_EMAIL,
    TERMS_AND_CONDITIONS,
    UPDATE_PASSWORD,
    CONFIGURE_TOTP,
    CONFIGURE_PASSKEY
  }

  static final String FLAGS = "requiredActions";
  static final String TERMS_ACCEPTED = "termsAccepted";

  private final UserStore users;
  private final PasskeyStore passkeys;
  private final SecondFactors secondFactors;
  private final boolean verifyEmail;
  private final String termsVersion;
  private final boolean secondFactorRequired;

  @Inject
  public RequiredActions(UserStore users, PasskeyStore passkeys, SecondFactors secondFactors, Config config) {
    this.users = users;
    this.passkeys = passkeys;
    this.secondFactors = secondFactors;
    this.verifyEmail = config.getBoolean("lattice.required-actions.verify-email");
    this.termsVersion = config.getString("lattice.required-actions.terms-version").trim();
    this.secondFactorRequired = config.getBoolean("lattice.second-factor.required");
  }

  /** The user's pending actions, in the order they are asked for. */
  public List<Action> pending(User user) {
    Set<String> flags = flags(user);
    String subject = user.getSubject();
    List<Action> pending = new ArrayList<>();
    if ((verifyEmail || flags.contains(Action.VERIFY_EMAIL.name()))
        && user.email().isPresent()
        && !Boolean.TRUE.equals(user.getClaim("email_verified", null))) {
      pending.add(Action.VERIFY_EMAIL);
    }
    if (!termsVersion.isEmpty() && !termsVersion.equals(user.getAttribute(TERMS_ACCEPTED))) {
      pending.add(Action.TERMS_AND_CONDITIONS);
    }
    if (flags.contains(Action.UPDATE_PASSWORD.name()) && user.passwordHash() != null) {
      pending.add(Action.UPDATE_PASSWORD);
    }
    boolean hasPasskey = !passkeys.forSubject(subject).isEmpty();
    boolean hasTotp = secondFactors.enrolled(subject);
    if ((flags.contains(Action.CONFIGURE_TOTP.name()) && !hasTotp)
        || (secondFactorRequired && !hasTotp && !hasPasskey)) {
      pending.add(Action.CONFIGURE_TOTP);
    }
    if (flags.contains(Action.CONFIGURE_PASSKEY.name()) && !hasPasskey) {
      pending.add(Action.CONFIGURE_PASSKEY);
    }
    return pending;
  }

  public String termsVersion() {
    return termsVersion;
  }

  /** Records that the user accepted the current terms. */
  public void acceptTerms(User user) {
    save(user, attributes -> attributes.put(TERMS_ACCEPTED, termsVersion));
  }

  /** Marks the account's email as verified. */
  public void markEmailVerified(User user) {
    Map<String, Object> claims = new HashMap<>(user.claims());
    claims.put("email_verified", true);
    users.save(new User(user.getSubject(), user.loginId(), user.passwordHash(), claims, clearedAttributes(user, Action.VERIFY_EMAIL), user.verifiedClaims()));
  }

  /** The account with {@code action} removed from its flags (for example after a password change). */
  public User cleared(User user, Action action) {
    return new User(user.getSubject(), user.loginId(), user.passwordHash(), user.claims(), clearedAttributes(user, action), user.verifiedClaims());
  }

  private Map<String, Object> clearedAttributes(User user, Action action) {
    Map<String, Object> attributes = new HashMap<>(user.attributes());
    Set<String> flags = flags(user);
    if (flags.remove(action.name())) {
      attributes.put(FLAGS, List.copyOf(flags));
    }
    return attributes;
  }

  private void save(User user, java.util.function.Consumer<Map<String, Object>> change) {
    Map<String, Object> attributes = new HashMap<>(user.attributes());
    change.accept(attributes);
    users.save(new User(user.getSubject(), user.loginId(), user.passwordHash(), user.claims(), attributes, user.verifiedClaims()));
  }

  private static Set<String> flags(User user) {
    Set<String> flags = new LinkedHashSet<>();
    if (user.getAttribute(FLAGS) instanceof List<?> list) {
      list.forEach(flag -> flags.add(String.valueOf(flag)));
    }
    return flags;
  }
}
