package com.lattice.oidc.user;

import com.google.inject.ImplementedBy;
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
}
