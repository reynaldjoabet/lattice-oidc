package com.lattice.oidc.handlers;

import com.lattice.oidc.common.Jsons;
import com.lattice.oidc.common.LatticeConfig;
import com.lattice.oidc.models.FederationConfig;
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

/** External OpenID Providers usable for login, loaded from {@code lattice.federation.file}. */
@Singleton
public final class Federations {

  public record Link(String id, String name) {}

  private static final Logger LOG = LoggerFactory.getLogger(Federations.class);

  private final Map<String, Federation> federations = new LinkedHashMap<>();

  @Inject
  public Federations(LatticeConfig config) {
    config.federationsFile().ifPresent(this::load);
  }

  private void load(String file) {
    FederationConfig parsed;
    try {
      parsed = Jsons.read(Files.readString(Path.of(file)), FederationConfig.class);
    } catch (IOException | RuntimeException e) {
      throw new IllegalStateException("Cannot load federations file " + file, e);
    }
    if (parsed.federations() == null) {
      return;
    }
    for (FederationConfig.Entry e : parsed.federations()) {
      if (e.id() == null
          || e.server() == null
          || e.server().issuer() == null
          || e.client() == null
          || e.client().clientId() == null
          || e.client().redirectUri() == null) {
        LOG.warn("Ignoring incomplete federation entry: {}", e.id());
        continue;
      }
      federations.put(e.id(), new Federation(e));
      LOG.info("Loaded ID federation {} ({})", e.id(), e.server().issuer());
    }
  }

  public Optional<Federation> get(String id) {
    return Optional.ofNullable(federations.get(id));
  }

  public List<Link> links() {
    return federations.values().stream().map(f -> new Link(f.id(), f.name())).toList();
  }
}
