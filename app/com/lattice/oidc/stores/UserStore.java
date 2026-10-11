package com.lattice.oidc.stores;

import com.google.inject.ImplementedBy;
import com.lattice.oidc.models.User;
import java.util.Optional;

/** Account lookup. The default implementation is in-memory; swap in a database-backed one. */
@ImplementedBy(InMemoryUserStore.class)
public interface UserStore {

  Optional<User> bySubject(String subject);

  Optional<User> byLoginId(String loginId);

  Optional<User> byEmail(String email);

  Optional<User> byPhoneNumber(String phoneNumber);

  /** Creates or replaces an account (used for users provisioned through ID federation). */
  void save(User user);

  /**
   * Replaces an account's password hash with {@code newHash} only if it is still {@code expectedHash};
   * returns whether it did.
   *
   * <p>Used to upgrade a hash made with older parameters, from a password that was just verified
   * against {@code expectedHash}. The condition matters: if the owner changed their password in the
   * meantime, a plain save would write the old password's hash back over the new one. A store that
   * cannot make the update conditional keeps this default, which changes nothing: the hash is simply
   * upgraded at a later sign-in.
   */
  default boolean replacePasswordHash(String subject, String expectedHash, String newHash) {
    return false;
  }

  /** Number of accounts (for the operator console). */
  default long count() {
    return 0;
  }
}
