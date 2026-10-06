package com.lattice.oidc.filters;

import com.lattice.oidc.models.UiSettings;
import com.typesafe.config.Config;
import java.util.concurrent.CompletionStage;
import java.util.function.Function;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import org.apache.pekko.stream.Materializer;
import play.mvc.Filter;
import play.mvc.Http;
import play.mvc.Result;

/** Makes the branding settings available to page templates as a request attribute. */
@Singleton
public final class UiFilter extends Filter {

  private final UiSettings settings;

  @Inject
  public UiFilter(Materializer materializer, Config config) {
    super(materializer);
    this.settings = UiSettings.from(config);
  }

  @Override
  public CompletionStage<Result> apply(
      Function<Http.RequestHeader, CompletionStage<Result>> next, Http.RequestHeader request) {
    return next.apply(request.addAttr(UiSettings.KEY, settings));
  }
}
