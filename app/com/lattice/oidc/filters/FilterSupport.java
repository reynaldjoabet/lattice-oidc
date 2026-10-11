package com.lattice.oidc.filters;

import java.util.concurrent.Executor;

/**
 * Why the filters here are {@code EssentialFilter}s and not Play's plain {@code Filter}s: a plain
 * {@code Filter} wraps the next action with {@code Accumulator.flatten}, which materializes a
 * stream, so a new actor under one shared supervisor, for every request and every filter. With six
 * filters that serialised all requests through that supervisor (about 30,000 requests per second
 * at best) and spent a fifth of the CPU time in stream set-up. An {@code EssentialFilter} only
 * transforms the accumulator the action already returns, with no stream of its own. Play's own
 * filters (CSRF, security headers, allowed hosts) are written the same way.
 */
final class FilterSupport {

  /** Runs the response transformations on the thread that completes them: they are tiny. */
  static final Executor DIRECT = Runnable::run;

  private FilterSupport() {}
}
