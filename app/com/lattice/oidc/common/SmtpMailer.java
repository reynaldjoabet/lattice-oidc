package com.lattice.oidc.common;

import com.lattice.oidc.metrics.Metrics;
import jakarta.mail.Authenticator;
import jakarta.mail.Message;
import jakarta.mail.MessagingException;
import jakarta.mail.PasswordAuthentication;
import jakarta.mail.Session;
import jakarta.mail.Transport;
import jakarta.mail.internet.InternetAddress;
import jakarta.mail.internet.MimeMessage;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Properties;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import play.inject.ApplicationLifecycle;

/**
 * {@link Mailer} over SMTP ({@code lattice.mail.smtp}). Without an SMTP host (development), the
 * message is written to the log instead, so reset links can be followed locally.
 */
@Singleton
public final class SmtpMailer implements Mailer {

  private static final Logger LOG = LoggerFactory.getLogger(SmtpMailer.class);

  private final LatticeConfig.Mail config;
  private final Session session;
  private final Metrics metrics;
  private final ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor();

  @Inject
  public SmtpMailer(LatticeConfig config, ApplicationLifecycle lifecycle, Metrics metrics) {
    this.metrics = metrics;
    this.config = config.mail();
    this.session = this.config.smtpHost().map(host -> session(host, this.config)).orElse(null);
    lifecycle.addStopHook(
        () -> {
          executor.shutdown();
          return java.util.concurrent.CompletableFuture.completedFuture(null);
        });
  }

  private static Session session(String host, LatticeConfig.Mail mail) {
    Properties properties = new Properties();
    properties.put("mail.smtp.host", host);
    properties.put("mail.smtp.port", String.valueOf(mail.smtpPort()));
    properties.put("mail.smtp.starttls.enable", String.valueOf(mail.startTls()));
    properties.put("mail.smtp.starttls.required", String.valueOf(mail.startTls()));
    properties.put("mail.smtp.connectiontimeout", "10000");
    properties.put("mail.smtp.timeout", "10000");
    properties.put("mail.smtp.writetimeout", "10000");
    if (mail.smtpUsername().isEmpty()) {
      return Session.getInstance(properties);
    }
    properties.put("mail.smtp.auth", "true");
    String username = mail.smtpUsername().get();
    String password = mail.smtpPassword().orElse("");
    return Session.getInstance(
        properties,
        new Authenticator() {
          @Override
          protected PasswordAuthentication getPasswordAuthentication() {
            return new PasswordAuthentication(username, password);
          }
        });
  }

  @Override
  public void send(String to, String subject, String text) {
    if (session == null) {
      LOG.info("No SMTP host configured (lattice.mail.smtp.host); email to {}:\nSubject: {}\n\n{}", to, subject, text);
      metrics.mail("logged", Duration.ZERO);
      return;
    }
    executor.execute(
        () -> {
          long started = System.nanoTime();
          try {
            MimeMessage message = new MimeMessage(session);
            message.setFrom(new InternetAddress(config.from()));
            message.setRecipient(Message.RecipientType.TO, new InternetAddress(to));
            message.setSubject(subject, StandardCharsets.UTF_8.name());
            message.setText(text, StandardCharsets.UTF_8.name());
            Transport.send(message);
            metrics.mail("sent", Duration.ofNanos(System.nanoTime() - started));
          } catch (MessagingException e) {
            metrics.mail("failed", Duration.ofNanos(System.nanoTime() - started));
            LOG.warn("Could not send email to {}: {}", to, e.getMessage());
          }
        });
  }
}
