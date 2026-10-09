package com.lattice.oidc.handlers;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import com.authlete.common.dto.CredentialIssuanceOrder;
import com.authlete.common.dto.CredentialRequestInfo;
import com.authlete.common.dto.IntrospectionResponse;
import com.lattice.oidc.common.JsonHelpers;
import com.lattice.oidc.models.User;
import com.lattice.oidc.stores.UserStore;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.Test;

/** Which credentials an access token permits, and what goes into them. */
public class CredentialOrderHandlerTest {

  private static final String PID = "urn:eu.europa.ec.eudi:pid:1";
  private static final String MDL = "org.iso.18013.5.1.mDL";

  private static final User ALICE =
      new User(
          "alice",
          "alice",
          null,
          Map.of("given_name", "Alice", "family_name", "Example", "birthdate", "1990-01-01", "email", "a@example.com"),
          Map.of(
              MDL,
              Map.of(
                  "org.iso.18013.5.1",
                  Map.of("family_name", "Example", "given_name", "Alice", "document_number", "D-1"))),
          List.of());

  private final CredentialOrderHandler handler =
      new CredentialOrderHandler(
          new UserStore() {
            public Optional<User> bySubject(String subject) {
              return "alice".equals(subject) ? Optional.of(ALICE) : Optional.empty();
            }

            public Optional<User> byLoginId(String loginId) {
              return Optional.empty();
            }

            public Optional<User> byEmail(String email) {
              return Optional.empty();
            }

            public Optional<User> byPhoneNumber(String phoneNumber) {
              return Optional.empty();
            }

            public void save(User user) {}
          });

  private static IntrospectionResponse token(String subject, Object issuable) {
    IntrospectionResponse r = new IntrospectionResponse();
    r.setSubject(subject);
    r.setIssuableCredentials(issuable == null ? null : JsonHelpers.write(issuable));
    return r;
  }

  private static final List<Map<String, Object>> PID_AND_MDL =
      List.of(
          Map.of("credential_configuration_id", "pid", "format", "dc+sd-jwt", "vct", PID),
          Map.of(
              "credential_configuration_id", "mdl",
              "format", "mso_mdoc",
              "doctype", MDL,
              "credential_metadata",
                  Map.of(
                      "claims",
                      List.of(
                          Map.of("path", List.of("org.iso.18013.5.1", "family_name")),
                          Map.of("path", List.of("org.iso.18013.5.1", "issue_date"))))));

  private Map<String, Object> payload(CredentialIssuanceOrder order) {
    return JsonHelpers.readMap(order.getCredentialPayload());
  }

  private void rejected(String error, IntrospectionResponse token, CredentialRequestInfo info) {
    try {
      handler.toOrder(CredentialOrderHandler.Context.SINGLE, token, info);
      fail("expected " + error);
    } catch (CredentialRequestException e) {
      assertEquals(error, e.errorCode());
    }
  }

  @Test
  public void sdJwtByConfigurationIdContainsOnlyTheTypesClaims() throws Exception {
    CredentialIssuanceOrder order =
        handler.toOrder(
            CredentialOrderHandler.Context.SINGLE,
            token("alice", PID_AND_MDL),
            new CredentialRequestInfo().setIdentifier("req-1").setFormat("dc+sd-jwt").setCredentialConfigurationId("pid"));
    Map<String, Object> credential = payload(order);
    assertEquals(PID, credential.get("vct"));
    assertEquals("alice", credential.get("sub"));
    assertEquals("Alice", credential.get("given_name"));
    assertFalse("claims outside the credential type are not disclosed", credential.containsKey("email"));
    assertEquals("req-1", order.getRequestIdentifier());
    assertFalse(order.isIssuanceDeferred());
  }

  @Test
  public void mdocContainsOnlyDeclaredClaimsAndComputedDates() throws Exception {
    CredentialIssuanceOrder order =
        handler.toOrder(
            CredentialOrderHandler.Context.SINGLE,
            token("alice", PID_AND_MDL),
            new CredentialRequestInfo().setFormat("mso_mdoc").setCredentialConfigurationId("mdl"));
    Map<String, Object> credential = payload(order);
    assertEquals(MDL, credential.get("doctype"));
    @SuppressWarnings("unchecked")
    Map<String, Object> namespace =
        (Map<String, Object>) ((Map<String, Object>) credential.get("claims")).get("org.iso.18013.5.1");
    assertEquals("Example", namespace.get("family_name"));
    assertTrue(String.valueOf(namespace.get("issue_date")).startsWith("cbor:1004("));
    assertFalse("undeclared claims are not issued", namespace.containsKey("document_number"));
  }

  @Test
  public void draftRequestsMustMatchAnIssuableFormatAndType() throws Exception {
    List<Map<String, Object>> issuable = List.of(Map.of("format", "vc+sd-jwt", "vct", PID));
    CredentialIssuanceOrder order =
        handler.toOrder(
            CredentialOrderHandler.Context.SINGLE,
            token("alice", issuable),
            new CredentialRequestInfo().setFormat("vc+sd-jwt").setDetails("{\"vct\":\"" + PID + "\"}"));
    assertEquals(PID, payload(order).get("vct"));

    rejected(
        "invalid_credential_request",
        token("alice", issuable),
        new CredentialRequestInfo()
            .setFormat("vc+sd-jwt")
            .setDetails("{\"vct\":\"https://credentials.example.com/identity_credential\"}"));
    rejected(
        "invalid_credential_request",
        token("alice", issuable),
        new CredentialRequestInfo().setFormat("vc+sd-jwt").setDetails("{}"));
  }

  @Test
  public void tokenMustPermitTheRequestedCredential() {
    rejected(
        "invalid_credential_request",
        token("alice", PID_AND_MDL),
        new CredentialRequestInfo().setFormat("dc+sd-jwt").setCredentialConfigurationId("other"));
    rejected(
        "invalid_credential_request",
        token("alice", null),
        new CredentialRequestInfo().setFormat("dc+sd-jwt").setCredentialConfigurationId("pid"));
  }

  @Test
  public void unknownSubjectFormatAndTypeAreRejected() {
    rejected(
        "invalid_credential_request",
        token("nobody", PID_AND_MDL),
        new CredentialRequestInfo().setFormat("dc+sd-jwt").setCredentialConfigurationId("pid"));
    rejected(
        "unsupported_credential_format",
        token("alice", PID_AND_MDL),
        new CredentialRequestInfo().setFormat("jwt_vc_json").setCredentialConfigurationId("pid"));
    rejected(
        "unsupported_credential_type",
        token("alice", List.of(Map.of("credential_configuration_id", "x", "format", "dc+sd-jwt", "vct", "urn:x"))),
        new CredentialRequestInfo().setFormat("dc+sd-jwt").setCredentialConfigurationId("x"));
  }
}
