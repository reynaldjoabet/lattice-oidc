package com.lattice.oidc.models;

import com.typesafe.config.Config;
import java.util.Optional;
import play.libs.typedmap.TypedKey;
import play.mvc.Http;

/** Branding of the end-user pages, from {@code lattice.ui}. Read by the page layout. */
public record UiSettings(
    String brandName,
    Optional<String> privacyUrl,
    Optional<String> termsUrl,
    Optional<String> helpUrl) {

  /** Request attribute under which {@code UiFilter} provides the settings to templates. */
  public static final TypedKey<UiSettings> KEY = TypedKey.create("uiSettings");

  /** Used when a page is rendered for a request that did not pass through the filters. */
  public static final UiSettings DEFAULT =
      new UiSettings("Lattice", Optional.empty(), Optional.empty(), Optional.empty());

  public static UiSettings from(Config root) {
    Config ui = root.getConfig("lattice.ui");
    return new UiSettings(
        ui.getString("brand-name"),
        optionalString(ui, "privacy-url"),
        optionalString(ui, "terms-url"),
        optionalString(ui, "help-url"));
  }

  public static UiSettings of(Http.RequestHeader request) {
    return request.attrs().getOptional(KEY).orElse(DEFAULT);
  }

  public boolean hasFooterLinks() {
    return privacyUrl.isPresent() || termsUrl.isPresent() || helpUrl.isPresent();
  }

  private static Optional<String> optionalString(Config config, String path) {
    String value = config.getString(path).trim();
    return value.isEmpty() ? Optional.empty() : Optional.of(value);
  }
}
