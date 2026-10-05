package com.lattice.oidc.security;

import static com.lattice.oidc.OidcTestSupport.app;
import static com.lattice.oidc.OidcTestSupport.get;
import static com.lattice.oidc.OidcTestSupport.post;
import static com.lattice.oidc.OidcTestSupport.route;
import static com.lattice.oidc.OidcTestSupport.withCsrf;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static play.test.Helpers.contentAsString;

import com.lattice.oidc.client.FakeAuthleteApi;
import com.lattice.oidc.models.User;
import com.lattice.oidc.stores.UserStore;
import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldap.listener.InMemoryListenerConfig;
import com.unboundid.ldap.sdk.Modification;
import com.unboundid.ldap.sdk.ModificationType;
import java.util.Map;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import play.Application;
import play.mvc.Result;
import play.test.Helpers;

/** Users from an LDAP directory, against a real (in-memory) LDAP server. */
public class LdapDirectoryTest {

  private static final String ADA_DN = "uid=ada,ou=people,dc=example,dc=com";

  private InMemoryDirectoryServer directory;
  private Application app;

  @Before
  public void start() throws Exception {
    InMemoryDirectoryServerConfig config = new InMemoryDirectoryServerConfig("dc=example,dc=com");
    config.addAdditionalBindCredentials("cn=lattice,dc=example,dc=com", "service-secret");
    config.setListenerConfigs(InMemoryListenerConfig.createLDAPConfig("ldap", 0));
    directory = new InMemoryDirectoryServer(config);
    directory.add("dn: dc=example,dc=com", "objectClass: top", "objectClass: domain", "dc: example");
    directory.add("dn: ou=people,dc=example,dc=com", "objectClass: organizationalUnit", "ou: people");
    directory.add(
        "dn: " + ADA_DN,
        "objectClass: inetOrgPerson",
        "uid: ada",
        "cn: Ada Lovelace",
        "givenName: Ada",
        "sn: Lovelace",
        "mail: ada@example.com",
        "userPassword: analytical-engine");
    directory.startListening();
    app =
        app(
            new FakeAuthleteApi(),
            Map.of(
                "lattice.ldap.enabled", true,
                "lattice.ldap.url", "ldap://127.0.0.1:" + directory.getListenPort(),
                "lattice.ldap.bind-dn", "cn=lattice,dc=example,dc=com",
                "lattice.ldap.bind-password", "service-secret",
                "lattice.ldap.base-dn", "ou=people,dc=example,dc=com"));
    Helpers.start(app);
  }

  @After
  public void stop() {
    Helpers.stop(app);
    directory.shutDown(true);
  }

  private LoginService login() {
    return app.injector().instanceOf(LoginService.class);
  }

  @Test
  public void aDirectoryUserSignsInAndIsCopiedIntoLattice() {
    Result signedIn =
        route(app, withCsrf(post("/account/login", Map.of("loginId", "ada", "password", "analytical-engine", "next", "account"))));
    assertEquals(303, signedIn.status());
    String account = contentAsString(route(app, get("/account").session(signedIn.session().data())));
    assertTrue(account.contains("Ada Lovelace"));
    assertTrue(account.contains("managed by your organisation"));

    User ada = app.injector().instanceOf(UserStore.class).byLoginId("ada").orElseThrow();
    assertEquals(ADA_DN, ada.getAttribute(LdapDirectory.DN_ATTRIBUTE));
    assertEquals("ada@example.com", ada.getClaim("email", null));
    assertEquals(true, ada.getClaim("email_verified", null));
    assertTrue("no Lattice password: it's checked in the directory", ada.passwordHash() == null);
  }

  @Test
  public void theDirectoryChecksThePassword() {
    assertEquals(LoginService.Outcome.INVALID_CREDENTIALS, login().authenticate("ada", "wrong").outcome());
    assertEquals(LoginService.Outcome.SUCCESS, login().authenticate("ada@example.com", "analytical-engine").outcome());
    assertEquals("unknown in the directory too", LoginService.Outcome.INVALID_CREDENTIALS, login().authenticate("nobody", "x").outcome());
  }

  @Test
  public void anEmptyPasswordIsNeverAnAnonymousBind() throws Exception {
    LdapDirectory ldap = app.injector().instanceOf(LdapDirectory.class);
    assertTrue(ldap.authenticate("ada", "").isEmpty());
  }

  @Test
  public void localAccountsStillUseTheirOwnPassword() {
    assertEquals(LoginService.Outcome.SUCCESS, login().authenticate("john", "john").outcome());
  }

  @Test
  public void theCopyIsRefreshedAtEachSignIn() throws Exception {
    login().authenticate("ada", "analytical-engine");
    directory.modify(ADA_DN, new Modification(ModificationType.REPLACE, "cn", "Augusta Ada King"));
    login().authenticate("ada", "analytical-engine");
    assertEquals("Augusta Ada King", app.injector().instanceOf(UserStore.class).byLoginId("ada").orElseThrow().getClaim("name", null));
  }

  @Test
  public void anUnreachableDirectoryIsNotAWrongPassword() {
    LoginService login = login();
    directory.shutDown(true);
    assertEquals(LoginService.Outcome.UNAVAILABLE, login.authenticate("ada", "analytical-engine").outcome());
    assertEquals(
        "an outage doesn't count towards the lockout",
        0L,
        app.injector().instanceOf(com.lattice.oidc.stores.CounterStore.class).count(LoginService.ACCOUNT_PREFIX + "ada"));
  }

  @Test
  public void aMisconfiguredDirectoryStopsStartup() {
    try {
      Application broken =
          app(
              new FakeAuthleteApi(),
              Map.of(
                  "lattice.ldap.enabled", true,
                  "lattice.ldap.url", "ldap://127.0.0.1:" + directory.getListenPort(),
                  "lattice.ldap.bind-dn", "cn=lattice,dc=example,dc=com",
                  "lattice.ldap.bind-password", "wrong-secret",
                  // A second app runs alongside the one from start(): it needs its own cluster port.
                  "pekko.remote.artery.canonical.port", 0));
      Helpers.stop(broken);
      org.junit.Assert.fail("startup should fail with a wrong bind password");
    } catch (com.google.inject.CreationException expected) {
      assertTrue(expected.getMessage(), expected.getMessage().contains("Could not connect to the LDAP directory"));
    }
  }
}
