package com.lattice.oidc.controllers;

import static com.lattice.oidc.OidcTestSupport.app;
import static com.lattice.oidc.OidcTestSupport.post;
import static com.lattice.oidc.OidcTestSupport.route;
import static com.lattice.oidc.OidcTestSupport.withCsrf;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static play.test.Helpers.contentAsString;

import com.authlete.common.dto.CredentialOfferCreateRequest;
import com.authlete.common.dto.CredentialOfferCreateResponse;
import com.authlete.common.dto.CredentialOfferInfo;
import com.lattice.oidc.client.FakeAuthleteApi;
import java.net.URI;
import java.util.Map;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import play.Application;
import play.mvc.Result;
import play.test.Helpers;

/** Creating a credential offer shows it for the wallet: QR code, transaction code and links. */
public class CredentialOfferTest {

  private final FakeAuthleteApi fake = new FakeAuthleteApi();
  private Application app;

  @Before
  public void start() {
    fake.answer(
        "credentialOfferCreate",
        args ->
            new CredentialOfferCreateResponse()
                .setAction(CredentialOfferCreateResponse.Action.CREATED)
                .setInfo(
                    new CredentialOfferInfo()
                        .setIdentifier("offer-1")
                        .setCredentialIssuer(URI.create("https://lattice.example"))
                        .setCredentialOffer("{\"credential_issuer\":\"https://lattice.example\"}")
                        .setTxCode("4821")));
    app = app(fake);
    Helpers.start(app);
  }

  @After
  public void stop() {
    Helpers.stop(app);
  }

  @Test
  public void createdOfferIsShownAsQrCodeWithTheTransactionCode() {
    Result r =
        route(
            app,
            withCsrf(
                post(
                    "/api/offer/issue",
                    Map.of(
                        "loginId", "john",
                        "password", "john",
                        "credentialConfigurationIds", "[\"IdentityCredential\"]",
                        "preAuthorizedCodeGrantIncluded", "on",
                        "txCode", "4821"))));
    assertEquals(200, r.status());
    String html = contentAsString(r);
    assertTrue(html.contains("Add your credential to a wallet"));
    assertTrue("the QR code is inline SVG", html.contains("<svg") && html.contains("QR code: credential offer"));
    assertTrue(html.contains("4821"));
    assertTrue(html.contains("IdentityCredential"));
    assertTrue(html.contains("credential_offer_uri=https%3A%2F%2Flattice.example%2Fapi%2Foffer%2Foffer-1"));
    CredentialOfferCreateRequest sent = fake.lastRequest("credentialOfferCreate");
    assertEquals("1001", sent.getSubject());
  }
}
