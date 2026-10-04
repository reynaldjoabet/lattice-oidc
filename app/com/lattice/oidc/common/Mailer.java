package com.lattice.oidc.common;

import com.google.inject.ImplementedBy;

/** Sends plain-text email to end-users (password reset links). */
@ImplementedBy(SmtpMailer.class)
public interface Mailer {

  /** Sends asynchronously; failures are logged, never shown to the end-user. */
  void send(String to, String subject, String text);
}
