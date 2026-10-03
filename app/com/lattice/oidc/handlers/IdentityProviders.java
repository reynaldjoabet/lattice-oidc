package com.lattice.oidc.handlers;

import com.lattice.oidc.common.Jsons;
import com.lattice.oidc.common.LatticeConfig;
import com.lattice.oidc.models.IdentityProviderConfig;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import javax.inject.Inject;
import javax.inject.Singleton;
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

  @Inject
  public IdentityProviders(LatticeConfig config) {
    config.identityProvidersFile().ifPresent(this::load);
  }

  private void load(String file) {
    IdentityProviderConfig parsed;
    try {
      parsed = Jsons.read(Files.readString(Path.of(file)), IdentityProviderConfig.class);
    } catch (IOException | RuntimeException e) {
      throw new IllegalStateException("Cannot load identity providers file " + file, e);
    }
    if (parsed.federations() == null) {
      return;
    }
    for (IdentityProviderConfig.Entry e : parsed.federations()) {
      if (e.id() == null
          || e.server() == null
          || e.server().issuer() == null
          || e.client() == null
          || e.client().clientId() == null
          || e.client().redirectUri() == null) {
        LOG.warn("Ignoring incomplete identity provider entry: {}", e.id());
        continue;
      }
      providers.put(e.id(), new IdentityProvider(e));
      LOG.info("Loaded identity provider {} ({})", e.id(), e.server().issuer());
    }
  }

  public Optional<IdentityProvider> get(String id) {
    return Optional.ofNullable(providers.get(id));
  }

  public List<Link> links() {
    return providers.values().stream().map(f -> new Link(f.id(), f.name())).toList();
  }
}
