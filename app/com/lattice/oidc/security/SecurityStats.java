package com.lattice.oidc.security;

import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import javax.inject.Singleton;

/**
 * Sign-in security figures for the operator console (screen 38): failed and locked sign-ins and
 * "not me" reports over the last 24 hours, on this node. Fed by {@link AuditService}; keeps at most
 * {@link #LIMIT} observations.
 */
@Singleton
public final class SecurityStats {

  static final int LIMIT = 20_000;
  private static final Duration WINDOW = Duration.ofHours(24);
  private static final DateTimeFormatter TIME =
      DateTimeFormatter.ofPattern("HH:mm 'UTC'", Locale.ENGLISH).withZone(ZoneOffset.UTC);

  private record Observation(Instant at, AuditService.Event event, String ip, String loginId) {}

  /** Failed sign-ins from one IP address. */
  public record Source(String ip, int failures, int loginIds, Instant lastSeen) {
    public String lastSeenTime() {
      return TIME.format(lastSeen);
    }
  }

  /**
   * The last 24 hours.
   *
   * @param hourly failed sign-ins per hour, oldest first (24 values)
   * @param spikeHour the start of the busiest hour, when it stands out (more than 3 times the median
   *     and at least 10)
   */
  public record Summary(int failed, List<Integer> hourly, Optional<Instant> spikeHour, int reports, List<Source> sources) {
    public Optional<String> spikeTime() {
      return spikeHour.map(TIME::format);
    }

    /** Bar heights in percent of the busiest hour. */
    public List<Integer> bars() {
      int maximum = hourly.stream().mapToInt(Integer::intValue).max().orElse(0);
      return hourly.stream().map(value -> maximum == 0 ? 0 : Math.max(4, value * 100 / maximum)).toList();
    }
  }

  private final Deque<Observation> observations = new ArrayDeque<>();

  void observe(AuditService.Event event, String ip, Object loginId) {
    if (event != AuditService.Event.LOGIN_FAILED
        && event != AuditService.Event.SECOND_FACTOR_FAILED
        && event != AuditService.Event.LOGIN_LOCKED
        && event != AuditService.Event.SIGN_IN_REPORTED) {
      return;
    }
    synchronized (observations) {
      observations.addLast(new Observation(Instant.now(), event, ip, loginId == null ? null : loginId.toString()));
      while (observations.size() > LIMIT) {
        observations.removeFirst();
      }
    }
  }

  /** Distinct login IDs locked within {@code lockout}. */
  public int lockedAccounts(Duration lockout) {
    Instant since = Instant.now().minus(lockout);
    Set<String> locked = new HashSet<>();
    for (Observation observation : snapshot()) {
      if (observation.event() == AuditService.Event.LOGIN_LOCKED && observation.at().isAfter(since) && observation.loginId() != null) {
        locked.add(observation.loginId().toLowerCase(Locale.ROOT));
      }
    }
    return locked.size();
  }

  public Summary summary() {
    Instant now = Instant.now();
    Instant firstHour = now.truncatedTo(ChronoUnit.HOURS).minus(Duration.ofHours(23));
    int[] hourly = new int[24];
    int failed = 0;
    int reports = 0;
    Map<String, int[]> failuresByIp = new HashMap<>();
    Map<String, Set<String>> loginIdsByIp = new HashMap<>();
    Map<String, Instant> lastSeenByIp = new HashMap<>();
    for (Observation observation : snapshot()) {
      if (observation.at().isBefore(now.minus(WINDOW))) {
        continue;
      }
      if (observation.event() == AuditService.Event.SIGN_IN_REPORTED) {
        reports++;
        continue;
      }
      failed++;
      long hour = Duration.between(firstHour, observation.at()).toHours();
      if (hour >= 0 && hour < 24) {
        hourly[(int) hour]++;
      }
      String ip = observation.ip() == null ? "unknown" : observation.ip();
      failuresByIp.computeIfAbsent(ip, key -> new int[1])[0]++;
      if (observation.loginId() != null) {
        loginIdsByIp.computeIfAbsent(ip, key -> new HashSet<>()).add(observation.loginId().toLowerCase(Locale.ROOT));
      }
      lastSeenByIp.merge(ip, observation.at(), (left, right) -> left.isAfter(right) ? left : right);
    }
    List<Source> sources = new ArrayList<>();
    failuresByIp.forEach(
        (ip, count) ->
            sources.add(new Source(ip, count[0], loginIdsByIp.getOrDefault(ip, Set.of()).size(), lastSeenByIp.get(ip))));
    sources.sort(Comparator.comparingInt(Source::failures).reversed());
    List<Integer> hours = new ArrayList<>();
    for (int value : hourly) {
      hours.add(value);
    }
    return new Summary(failed, hours, spike(hourly, firstHour), reports, sources.stream().limit(10).toList());
  }

  private static Optional<Instant> spike(int[] hourly, Instant firstHour) {
    int[] sorted = hourly.clone();
    java.util.Arrays.sort(sorted);
    int median = sorted[sorted.length / 2];
    int busiest = 0;
    for (int index = 1; index < hourly.length; index++) {
      if (hourly[index] > hourly[busiest]) {
        busiest = index;
      }
    }
    return hourly[busiest] >= 10 && hourly[busiest] > 3 * median
        ? Optional.of(firstHour.plus(Duration.ofHours(busiest)))
        : Optional.empty();
  }

  private List<Observation> snapshot() {
    synchronized (observations) {
      return List.copyOf(observations);
    }
  }
}
