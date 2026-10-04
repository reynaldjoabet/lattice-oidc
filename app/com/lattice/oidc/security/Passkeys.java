package com.lattice.oidc.security;

import com.lattice.oidc.common.LatticeConfig;
import com.lattice.oidc.models.Passkey;
import com.lattice.oidc.models.UiSettings;
import com.lattice.oidc.models.User;
import com.lattice.oidc.stores.PasskeyStore;
import com.yubico.webauthn.AssertionRequest;
import com.yubico.webauthn.AssertionResult;
import com.yubico.webauthn.CredentialRepository;
import com.yubico.webauthn.FinishAssertionOptions;
import com.yubico.webauthn.FinishRegistrationOptions;
import com.yubico.webauthn.RegisteredCredential;
import com.yubico.webauthn.RegistrationResult;
import com.yubico.webauthn.RelyingParty;
import com.yubico.webauthn.StartAssertionOptions;
import com.yubico.webauthn.StartRegistrationOptions;
import com.yubico.webauthn.data.AuthenticatorSelectionCriteria;
import com.yubico.webauthn.data.AuthenticatorTransport;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.PublicKeyCredential;
import com.yubico.webauthn.data.PublicKeyCredentialCreationOptions;
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor;
import com.yubico.webauthn.data.PublicKeyCredentialRequestOptions;
import com.yubico.webauthn.data.RelyingPartyIdentity;
import com.yubico.webauthn.data.ResidentKeyRequirement;
import com.yubico.webauthn.data.UserIdentity;
import com.yubico.webauthn.data.UserVerificationRequirement;
import com.yubico.webauthn.data.exception.Base64UrlException;
import com.yubico.webauthn.exception.AssertionFailedException;
import com.yubico.webauthn.exception.RegistrationFailedException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;
import java.util.stream.Collectors;
import javax.inject.Inject;
import javax.inject.Singleton;

/**
 * Passkeys (WebAuthn) for Lattice accounts, on Yubico's WebAuthn server library.
 *
 * <ul>
 *   <li>Registration requires a discoverable credential (a passkey) and user verification
 *       (fingerprint, face, PIN), so a passkey alone is a phishing-resistant multi-factor sign-in.
 *   <li>Sign-in is usernameless: the browser offers the passkeys it has for this site (conditional
 *       UI), and the account is found from the credential.
 *   <li>Verification of a known user (step-up, re-authentication, approvals) only accepts that
 *       user's passkeys. Approvals bind the WebAuthn challenge to the details being approved.
 * </ul>
 */
@Singleton
public final class Passkeys {

  /** Thrown when a ceremony fails (bad response, unknown passkey, verification failed). */
  public static final class PasskeyException extends Exception {
    private static final long serialVersionUID = 1L;

    PasskeyException(String message, Throwable cause) {
      super(message, cause);
    }
  }

  /** The outcome of a successful sign-in or verification. */
  public record Verified(String subject, Passkey passkey) {}

  private static final SecureRandom RANDOM = new SecureRandom();

  private final PasskeyStore store;
  private final LatticeConfig config;
  private final RelyingParty relyingParty;

  @Inject
  public Passkeys(PasskeyStore store, LatticeConfig config) {
    this.store = store;
    this.config = config;
    this.relyingParty =
        RelyingParty.builder()
            .identity(
                RelyingPartyIdentity.builder()
                    .id(config.passkeys().rpId())
                    .name(UiSettings.DEFAULT.brandName())
                    .build())
            .credentialRepository(new Repository(store))
            .origins(new HashSet<>(config.passkeys().origins()))
            .build();
  }

  /** The ACR value of a passkey sign-in (phishing-resistant). */
  public String acr() {
    return config.passkeys().acr();
  }

  public boolean hasPasskeys(String subject) {
    return !store.forSubject(subject).isEmpty();
  }

  /** Whether to show the "create a passkey" offer now (no passkey, not offered recently). */
  public boolean offerDue(String subject) {
    if (config.passkeys().offerInterval().isZero() || hasPasskeys(subject)) {
      return false;
    }
    return store
        .offeredAt(subject)
        .map(at -> at.plus(config.passkeys().offerInterval()).isBefore(Instant.now()))
        .orElse(true);
  }

  public void markOffered(String subject) {
    store.markOffered(subject, Instant.now());
  }

  // ---------------------------------------------------------------- registration

  /** Options for {@code navigator.credentials.create()}; keep them to finish the registration. */
  public PublicKeyCredentialCreationOptions startRegistration(User user) {
    return relyingParty.startRegistration(
        StartRegistrationOptions.builder()
            .user(
                UserIdentity.builder()
                    .name(user.loginId() != null ? user.loginId() : user.getSubject())
                    .displayName(user.displayName())
                    .id(handle(user.getSubject()))
                    .build())
            .authenticatorSelection(
                AuthenticatorSelectionCriteria.builder()
                    .residentKey(ResidentKeyRequirement.REQUIRED)
                    .userVerification(UserVerificationRequirement.REQUIRED)
                    .build())
            .build());
  }

  /** Verifies the browser's response and stores the new passkey under {@code name}. */
  public Passkey finishRegistration(
      User user, PublicKeyCredentialCreationOptions options, String responseJson, String name)
      throws PasskeyException {
    try {
      RegistrationResult result =
          relyingParty.finishRegistration(
              FinishRegistrationOptions.builder()
                  .request(options)
                  .response(PublicKeyCredential.parseRegistrationResponseJson(responseJson))
                  .build());
      Set<String> transports =
          result.getKeyId().getTransports().orElse(new TreeSet<>()).stream()
              .map(AuthenticatorTransport::getId)
              .collect(Collectors.toSet());
      Passkey passkey =
          new Passkey(
              result.getKeyId().getId().getBase64Url(),
              user.getSubject(),
              options.getUser().getId().getBase64Url(),
              result.getPublicKeyCose().getBase64Url(),
              result.getSignatureCount(),
              name,
              Instant.now(),
              Optional.empty(),
              result.isBackedUp(),
              transports);
      store.save(passkey);
      return passkey;
    } catch (RegistrationFailedException | IOException | RuntimeException e) {
      throw new PasskeyException("Passkey registration failed: " + e.getMessage(), e);
    }
  }

  // ---------------------------------------------------------------- sign-in and verification

  /** Usernameless sign-in: any passkey of any account on this site. */
  public AssertionRequest startSignIn() {
    return relyingParty.startAssertion(
        StartAssertionOptions.builder().userVerification(UserVerificationRequirement.REQUIRED).build());
  }

  /** Verification of a known account (step-up, re-authentication): only its passkeys. */
  public AssertionRequest startVerification(String subject) {
    return relyingParty.startAssertion(
        StartAssertionOptions.builder()
            .username(subject)
            .userVerification(UserVerificationRequirement.REQUIRED)
            .build());
  }

  /**
   * Verification of a known account that also signs {@code details} (for example the payment of a
   * CIBA request): the challenge is SHA-256(random || details), so the signature covers exactly
   * what the page showed.
   */
  public AssertionRequest startApproval(String subject, String details) {
    byte[] random = new byte[32];
    RANDOM.nextBytes(random);
    byte[] challenge = sha256(random, details.getBytes(StandardCharsets.UTF_8));
    List<PublicKeyCredentialDescriptor> allowed =
        store.forSubject(subject).stream()
            .map(passkey -> PublicKeyCredentialDescriptor.builder().id(bytes(passkey.id())).build())
            .toList();
    return AssertionRequest.builder()
        .publicKeyCredentialRequestOptions(
            PublicKeyCredentialRequestOptions.builder()
                .challenge(new ByteArray(challenge))
                .rpId(config.passkeys().rpId())
                .allowCredentials(allowed)
                .userVerification(UserVerificationRequirement.REQUIRED)
                .timeout(120_000L)
                .build())
        .username(subject)
        .build();
  }

  /** Verifies the browser's response to {@code request}; records the use of the passkey. */
  public Verified finishAssertion(AssertionRequest request, String responseJson) throws PasskeyException {
    try {
      AssertionResult result =
          relyingParty.finishAssertion(
              FinishAssertionOptions.builder()
                  .request(request)
                  .response(PublicKeyCredential.parseAssertionResponseJson(responseJson))
                  .build());
      if (!result.isSuccess() || !result.isUserVerified()) {
        throw new PasskeyException("The passkey was not verified.", null);
      }
      String id = result.getCredential().getCredentialId().getBase64Url();
      Passkey passkey =
          store.byId(id).orElseThrow(() -> new PasskeyException("Unknown passkey.", null));
      Passkey used = passkey.used(result.getSignatureCount(), Instant.now());
      store.save(used);
      return new Verified(result.getUsername(), used);
    } catch (AssertionFailedException | IOException | RuntimeException e) {
      throw new PasskeyException("Passkey verification failed: " + e.getMessage(), e);
    }
  }

  private ByteArray handle(String subject) {
    return bytes(store.userHandle(subject));
  }

  static ByteArray bytes(String base64Url) {
    try {
      return ByteArray.fromBase64Url(base64Url);
    } catch (Base64UrlException e) {
      throw new IllegalStateException(e);
    }
  }

  private static byte[] sha256(byte[]... parts) {
    try {
      MessageDigest digest = MessageDigest.getInstance("SHA-256");
      for (byte[] part : parts) {
        digest.update(part);
      }
      return digest.digest();
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException(e);
    }
  }

  /** Yubico's view of the passkey store. The WebAuthn "username" is the account's subject. */
  private static final class Repository implements CredentialRepository {

    private final PasskeyStore store;

    Repository(PasskeyStore store) {
      this.store = store;
    }

    @Override
    public Set<PublicKeyCredentialDescriptor> getCredentialIdsForUsername(String subject) {
      return store.forSubject(subject).stream()
          .map(passkey -> PublicKeyCredentialDescriptor.builder().id(bytes(passkey.id())).build())
          .collect(Collectors.toSet());
    }

    @Override
    public Optional<ByteArray> getUserHandleForUsername(String subject) {
      return Optional.of(bytes(store.userHandle(subject)));
    }

    @Override
    public Optional<String> getUsernameForUserHandle(ByteArray userHandle) {
      return store.subjectForUserHandle(userHandle.getBase64Url());
    }

    @Override
    public Optional<RegisteredCredential> lookup(ByteArray credentialId, ByteArray userHandle) {
      return store
          .byId(credentialId.getBase64Url())
          .filter(passkey -> passkey.userHandle().equals(userHandle.getBase64Url()))
          .map(Repository::registered);
    }

    @Override
    public Set<RegisteredCredential> lookupAll(ByteArray credentialId) {
      return store.byId(credentialId.getBase64Url()).map(Repository::registered).stream()
          .collect(Collectors.toSet());
    }

    private static RegisteredCredential registered(Passkey passkey) {
      return RegisteredCredential.builder()
          .credentialId(bytes(passkey.id()))
          .userHandle(bytes(passkey.userHandle()))
          .publicKeyCose(bytes(passkey.publicKeyCose()))
          .signatureCount(passkey.signatureCount())
          .build();
    }
  }
}
