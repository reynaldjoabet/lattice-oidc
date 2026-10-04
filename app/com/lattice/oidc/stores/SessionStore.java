package com.lattice.oidc.stores;

import com.google.inject.ImplementedBy;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * Server-side login sessions, shared by every server. A session ends when it is ended explicitly,
 * when it reaches {@code expiresAt} (the maximum lifetime), or when it has been idle too long
 * (checked by {@code UserSessions} from {@code lastSeenAt}).
 */
@ImplementedBy(InMemorySessionStore.class)
public interface SessionStore {

  /** A login session: who, from where, how they signed in, and when it was created and last used. */
  record Session(
      String id,
      String subject,
      String userAgent,
      String ip,
      String method,
      Instant createdAt,
      Instant lastSeenAt,
      Instant expiresAt) {}

  void create(Session session);

  /** The session, unless it has ended or passed {@code expiresAt}. */
  Optional<Session> find(String id);

  /** Records activity, at most once per {@code interval} to keep writes rare. */
  void touch(String id, Instant now, Duration interval);

  /** Ends the session; returns it if it existed. */
  Optional<Session> end(String id);

  /** The account's sessions that haven't passed {@code expiresAt}. */
  List<Session> forSubject(String subject);

  /** Records that a client obtained tokens in the session (for back-channel logout). */
  void addClient(String id, String clientIdentifier);

  Set<String> clients(String id);

  /** Sessions that haven't passed {@code expiresAt} (for the operator console). */
  long countActive();
}
