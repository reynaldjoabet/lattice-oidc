package com.lattice.oidc.models;

import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;

/**
 * What the consent page shows for an Open Banking consent: the account the data comes from, each
 * permission in plain language (with its code) and when access ends.
 */
public record ObbConsentView(String account, List<Permission> permissions, Optional<String> expires) {

  public record Permission(String label, String code) {}

  private static final DateTimeFormatter DATE =
      DateTimeFormatter.ofPattern("d MMM yyyy", Locale.ENGLISH).withZone(ZoneOffset.UTC);

  private static final Map<String, String> LABELS =
      Map.ofEntries(
          Map.entry("ACCOUNTS_READ", "Account details"),
          Map.entry("ACCOUNTS_BALANCES_READ", "Balances"),
          Map.entry("ACCOUNTS_TRANSACTIONS_READ", "Transactions"),
          Map.entry("ACCOUNTS_OVERDRAFT_LIMITS_READ", "Overdraft limits"),
          Map.entry("CREDIT_CARDS_ACCOUNTS_READ", "Credit card accounts"),
          Map.entry("CREDIT_CARDS_ACCOUNTS_BILLS_READ", "Credit card bills"),
          Map.entry("CREDIT_CARDS_ACCOUNTS_BILLS_TRANSACTIONS_READ", "Credit card bill transactions"),
          Map.entry("CREDIT_CARDS_ACCOUNTS_LIMITS_READ", "Credit card limits"),
          Map.entry("CREDIT_CARDS_ACCOUNTS_TRANSACTIONS_READ", "Credit card transactions"),
          Map.entry("CUSTOMERS_PERSONAL_IDENTIFICATIONS_READ", "Personal identification"),
          Map.entry("CUSTOMERS_PERSONAL_ADITTIONALINFO_READ", "Personal details"),
          Map.entry("CUSTOMERS_BUSINESS_IDENTIFICATIONS_READ", "Business identification"),
          Map.entry("CUSTOMERS_BUSINESS_ADITTIONALINFO_READ", "Business details"),
          Map.entry("LOANS_READ", "Loans"),
          Map.entry("FINANCINGS_READ", "Financings"),
          Map.entry("INVOICE_FINANCINGS_READ", "Invoice financings"),
          Map.entry("UNARRANGED_ACCOUNTS_OVERDRAFT_READ", "Unarranged overdraft"),
          Map.entry("RESOURCES_READ", "Which of your accounts and products are shared"));

  public static ObbConsentView of(Consent consent, String account) {
    List<Permission> permissions =
        consent.permissions().stream()
            .map(code -> new Permission(LABELS.getOrDefault(code, code), code))
            .toList();
    return new ObbConsentView(account, permissions, date(consent.expirationDateTime()));
  }

  private static Optional<String> date(String iso) {
    if (iso == null || iso.isBlank()) {
      return Optional.empty();
    }
    try {
      return Optional.of(DATE.format(Instant.parse(iso)));
    } catch (DateTimeParseException e) {
      return Optional.of(iso);
    }
  }
}
