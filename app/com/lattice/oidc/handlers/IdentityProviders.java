package com.lattice.oidc.handlers;

import com.lattice.oidc.common.JsonHelpers;
import com.lattice.oidc.common.LatticeConfig;
import com.lattice.oidc.models.IdentityProviderConfig;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The upstream identity providers end-users can sign in with (identity brokering), loaded from the
 * JSON file named by {@code lattice.identity-providers.file}. Provides lookup by id for the broker
 * endpoints and the list of links shown on the authorization page.
 */
@Singleton
public final class IdentityProviders {

  public record Link(String id, String name) {}

  private static final Logger LOG = LoggerFactory.getLogger(IdentityProviders.class);

  private final Map<String, IdentityProvider> providers = new LinkedHashMap<>();
  private final Map<String, IdentityProvider> byDomain = new LinkedHashMap<>();

  @Inject
  public IdentityProviders(LatticeConfig config) {
    config.identityProvidersFile().ifPresent(this::load);
  }

  private void load(String file) {
    IdentityProviderConfig parsed;
    try {
      parsed = JsonHelpers.read(Files.readString(Path.of(file)), IdentityProviderConfig.class);
    } catch (IOException | RuntimeException e) {
      throw new IllegalStateException("Cannot load identity providers file " + file, e);
    }
    if (parsed.identityProviders() == null) {
      return;
    }
    for (IdentityProviderConfig.Entry entry : parsed.identityProviders()) {
      if (entry.id() == null
          || entry.server() == null
          || entry.server().issuer() == null
          || entry.client() == null
          || entry.client().clientId() == null
          || entry.client().redirectUri() == null) {
        LOG.warn("Ignoring incomplete identity provider entry: {}", entry.id());
        continue;
      }
      IdentityProvider provider = new IdentityProvider(entry);
      providers.put(entry.id(), provider);
      if (entry.domains() != null) {
        for (String domain : entry.domains()) {
          byDomain.put(domain.trim().toLowerCase(java.util.Locale.ROOT), provider);
        }
      }
      LOG.info("Loaded identity provider {} ({})", entry.id(), entry.server().issuer());
    }
  }

  public Optional<IdentityProvider> get(String id) {
    return Optional.ofNullable(providers.get(id));
  }

  /** The provider whose users have this email address's domain, if one lists it. */
  public Optional<IdentityProvider> forEmail(String email) {
    if (email == null || email.indexOf('@') < 0) {
      return Optional.empty();
    }
    String domain = email.substring(email.lastIndexOf('@') + 1).trim().toLowerCase(java.util.Locale.ROOT);
    return Optional.ofNullable(byDomain.get(domain));
  }

  public List<Link> links() {
    return providers.values().stream().map(provider -> new Link(provider.id(), provider.name())).toList();
  }
}
