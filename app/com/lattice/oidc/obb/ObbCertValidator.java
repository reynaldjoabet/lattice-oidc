package com.lattice.oidc.obb;

import com.lattice.oidc.config.LatticeConfig;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.cert.CertPathValidator;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import javax.inject.Inject;
import javax.inject.Singleton;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** Validates client certificate chains against the configured Open Banking Brasil roots. */
@Singleton
public final class ObbCertValidator {

  private static final Logger LOG = LoggerFactory.getLogger(ObbCertValidator.class);

  private final Set<TrustAnchor> anchors = new HashSet<>();

  @Inject
  public ObbCertValidator(LatticeConfig config) {
    for (String file : config.obbRootCertificates()) {
      try (InputStream in = Files.newInputStream(Path.of(file))) {
        X509Certificate cert =
            (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(in);
        anchors.add(new TrustAnchor(cert, null));
        LOG.info("Loaded OBB root certificate {}", file);
      } catch (IOException | GeneralSecurityException e) {
        throw new IllegalStateException("Cannot load OBB root certificate " + file, e);
      }
    }
  }

  public boolean configured() {
    return !anchors.isEmpty();
  }

  /** Throws when the chain (PEM, leaf first) does not lead to a configured root. */
  public void validate(String[] pemChain) throws GeneralSecurityException {
    if (anchors.isEmpty()) {
      throw new GeneralSecurityException("No OBB root certificates are configured.");
    }
    if (pemChain == null || pemChain.length == 0) {
      throw new GeneralSecurityException("The request does not contain a client certificate.");
    }
    CertificateFactory factory = CertificateFactory.getInstance("X.509");
    List<Certificate> certs = new ArrayList<>();
    for (String pem : pemChain) {
      certs.add(
          factory.generateCertificate(
              new ByteArrayInputStream(normalize(pem).getBytes(StandardCharsets.US_ASCII))));
    }
    PKIXParameters params = new PKIXParameters(anchors);
    params.setRevocationEnabled(false);
    CertPathValidator.getInstance("PKIX").validate(factory.generateCertPath(certs), params);
  }

  public boolean isValid(String[] pemChain) {
    try {
      validate(pemChain);
      return true;
    } catch (GeneralSecurityException e) {
      return false;
    }
  }

  private static String normalize(String pem) {
    String trimmed = pem.trim();
    if (trimmed.startsWith("-----BEGIN CERTIFICATE")) {
      return trimmed;
    }
    return "-----BEGIN CERTIFICATE-----\n" + trimmed + "\n-----END CERTIFICATE-----\n";
  }
}
