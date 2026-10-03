package com.lattice.oidc.controllers;

import static com.lattice.oidc.OidcTestSupport.app;
import static com.lattice.oidc.OidcTestSupport.route;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static play.test.Helpers.contentAsString;

import com.authlete.common.dto.CredentialDeferredIssueRequest;
import com.authlete.common.dto.CredentialDeferredIssueResponse;
import com.authlete.common.dto.CredentialDeferredParseResponse;
import com.authlete.common.dto.CredentialRequestInfo;
import com.authlete.common.dto.CredentialSingleIssueRequest;
import com.authlete.common.dto.CredentialSingleIssueResponse;
import com.authlete.common.dto.CredentialSingleParseResponse;
import com.authlete.common.dto.IntrospectionRequest;
import com.authlete.common.dto.IntrospectionResponse;
import com.lattice.oidc.client.FakeAuthleteApi;
import com.lattice.oidc.common.Jsons;
import java.util.List;
import java.util.Map;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import play.Application;
import play.mvc.Http;
import play.mvc.Result;
import play.test.Helpers;

/** OID4VCI credential and deferred credential endpoints: token checks and issuance orders. */
public class CredentialEndpointTest {

  private static final String PID = "urn:eu.europa.ec.eudi:pid:1";

  private final FakeAuthleteApi fake = new FakeAuthleteApi();
  private Application app;

  @Before
  public void start() {
    fake.answer("introspection", args -> token(IntrospectionResponse.Action.OK))
        .answer(
            "credentialSingleParse",
            args ->
                new CredentialSingleParseResponse()
                    .setAction(CredentialSingleParseResponse.Action.OK)
                    .setInfo(pidRequest()))
        .answer(
            "credentialSingleIssue",
            args ->
                new CredentialSingleIssueResponse()
                    .setAction(CredentialSingleIssueResponse.Action.OK)
                    .setResponseContent("{\"credentials\":[{\"credential\":\"eyJ...\"}]}"))
        .answer(
            "credentialDeferredParse",
            args ->
                new CredentialDeferredParseResponse()
                    .setAction(CredentialDeferredParseResponse.Action.OK)
                    .setInfo(pidRequest()))
        .answer(
            "credentialDeferredIssue",
            args ->
                new CredentialDeferredIssueResponse()
                    .setAction(CredentialDeferredIssueResponse.Action.OK)
                    .setResponseContent("{\"credentials\":[{\"credential\":\"eyJ...\"}]}"));
    app = app(fake);
    Helpers.start(app);
  }

  @After
  public void stop() {
    Helpers.stop(app);
  }

  private static CredentialRequestInfo pidRequest() {
    return new CredentialRequestInfo()
        .setIdentifier("req-1")
        .setFormat("dc+sd-jwt")
        .setCredentialConfigurationId("pid");
  }

  private static IntrospectionResponse token(IntrospectionResponse.Action action) {
    IntrospectionResponse r = new IntrospectionResponse();
    r.setAction(action);
    r.setSubject("1001");
    r.setIssuableCredentials(
        Jsons.write(List.of(Map.of("credential_configuration_id", "pid", "format", "dc+sd-jwt", "vct", PID))));
    r.setResponseContent("Bearer error=\"invalid_token\"");
    return r;
  }

  private static Http.RequestBuilder credentialRequest(String uri, String authorization) {
    Http.RequestBuilder b =
        new Http.RequestBuilder()
            .method("POST")
            .uri(uri)
            .bodyText("{\"credential_configuration_id\":\"pid\"}")
            .header("Content-Type", "application/json");
    return authorization == null ? b : b.header("Authorization", authorization);
  }

  @Test
  public void missingAccessTokenIsRejectedWithoutCallingAuthlete() {
    Result r = route(app, credentialRequest("/api/credential", null));
    assertEquals(400, r.status());
    assertTrue(r.header("WWW-Authenticate").orElse("").contains("invalid_token"));
    assertEquals(0, fake.count("introspection"));
  }

  @Test
  public void invalidAccessTokenStopsBeforeParsing() {
    fake.answer("introspection", args -> token(IntrospectionResponse.Action.UNAUTHORIZED));
    Result r = route(app, credentialRequest("/api/credential", "Bearer expired"));
    assertEquals(401, r.status());
    assertEquals(0, fake.count("credentialSingleParse"));
  }

  @Test
  public void dpopProofIsCheckedAgainstThisEndpoint() {
    route(app, credentialRequest("/api/credential", "DPoP at-1").header("DPoP", "proof-jwt"));
    IntrospectionRequest sent = fake.lastRequest("introspection");
    assertEquals("at-1", sent.getToken());
    assertEquals("proof-jwt", sent.getDpop());
    assertEquals("http://localhost/api/credential", sent.getHtu());
  }

  @Test
  public void permittedCredentialIsIssuedWithTheUsersClaims() {
    Result r = route(app, credentialRequest("/api/credential", "Bearer at-1"));
    assertEquals(200, r.status());
    CredentialSingleIssueRequest issue = fake.lastRequest("credentialSingleIssue");
    assertEquals("at-1", issue.getAccessToken());
    Map<String, Object> payload = Jsons.readMap(issue.getOrder().getCredentialPayload());
    assertEquals("1001", payload.get("sub"));
    assertEquals("Smith", payload.get("family_name"));
  }

  @Test
  public void credentialTheTokenDoesNotPermitIsRejected() {
    fake.answer(
        "credentialSingleParse",
        args ->
            new CredentialSingleParseResponse()
                .setAction(CredentialSingleParseResponse.Action.OK)
                .setInfo(pidRequest().setCredentialConfigurationId("mdl")));
    Result r = route(app, credentialRequest("/api/credential", "Bearer at-1"));
    assertEquals(400, r.status());
    assertTrue(contentAsString(r).contains("invalid_credential_request"));
    assertEquals(0, fake.count("credentialSingleIssue"));
  }

  @Test
  public void deferredQueryParameterDefersIssuance() {
    fake.answer(
        "credentialSingleIssue",
        args ->
            new CredentialSingleIssueResponse()
                .setAction(CredentialSingleIssueResponse.Action.ACCEPTED)
                .setResponseContent("{\"transaction_id\":\"tx-1\"}"));
    Result r = route(app, credentialRequest("/api/credential?deferred=true", "Bearer at-1"));
    assertEquals(202, r.status());
    CredentialSingleIssueRequest issue = fake.lastRequest("credentialSingleIssue");
    assertTrue(issue.getOrder().isIssuanceDeferred());
  }

  @Test
  public void deferredCredentialIsIssuedOnceReady() {
    Result r = route(app, credentialRequest("/api/deferred_credential", "Bearer at-1"));
    assertEquals(200, r.status());
    CredentialDeferredIssueRequest issue = fake.lastRequest("credentialDeferredIssue");
    assertEquals("1001", Jsons.readMap(issue.getOrder().getCredentialPayload()).get("sub"));
  }

  @Test
  public void nonceEndpointNeedsNoToken() {
    fake.answer(
        "credentialNonce",
        args ->
            new com.authlete.common.dto.CredentialNonceResponse()
                .setAction(com.authlete.common.dto.CredentialNonceResponse.Action.OK)
                .setResponseContent("{\"c_nonce\":\"n-1\"}"));
    Result r = route(app, new Http.RequestBuilder().method("POST").uri("/api/nonce"));
    assertEquals(200, r.status());
    assertEquals(0, fake.count("introspection"));
  }
}
