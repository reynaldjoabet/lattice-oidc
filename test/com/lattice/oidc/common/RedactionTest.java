package com.lattice.oidc.common;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

public class RedactionTest {

  @Test
  public void redactsJsonMembersAndFormParameters() {
    assertEquals(
        "{\"client_secret\":\"REDACTED\",\"client_id\":\"c1\",\"refresh_token\" : \"REDACTED\"}",
        Redaction.redact(
            "{\"client_secret\":\"s3cr3t\",\"client_id\":\"c1\",\"refresh_token\" : \"rt\"}"));
    assertEquals(
        "grant_type=authorization_code&code=REDACTED&redirect_uri=https://c/cb",
        Redaction.redact("grant_type=authorization_code&code=abc&redirect_uri=https://c/cb"));
  }
}
