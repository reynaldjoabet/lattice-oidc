package com.lattice.oidc.filters;

import com.lattice.oidc.models.UiSettings;
import com.typesafe.config.Config;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import play.mvc.EssentialAction;
import play.mvc.EssentialFilter;

/** Makes the branding settings available to page templates as a request attribute. */
@Singleton
public final class UiFilter extends EssentialFilter {

  private final UiSettings settings;

  @Inject
  public UiFilter(Config config) {
    this.settings = UiSettings.from(config);
  }

  @Override
  public EssentialAction apply(EssentialAction next) {
    return EssentialAction.of(request -> next.apply(request.addAttr(UiSettings.KEY, settings)));
  }
}
