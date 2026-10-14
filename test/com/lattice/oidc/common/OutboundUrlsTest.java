package com.lattice.oidc.common;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.net.InetAddress;
import java.util.Optional;
import org.junit.Test;

/** Client-chosen URLs never lead to loopback, private or link-local addresses. */
public class OutboundUrlsTest {

  private static boolean refused(String url) {
    return OutboundUrls.problem(url, false).isPresent();
  }

  @Test
  public void internalAddressesAreRefused() {
    for (String url :
        new String[] {
          "https://127.0.0.1/cb",
          "https://localhost/cb",
          "https://10.1.2.3/cb",
          "https://172.16.0.1/cb",
          "https://192.168.1.1/cb",
          "http://169.254.169.254/latest/meta-data/",
          "https://100.64.0.1/cb",
          "https://0.0.0.0/cb",
          "https://[::1]/cb",
          "https://[fc00::1]/cb",
          "https://[fd12:3456::1]/cb",
          "https://[fe80::1]/cb",
          "https://[::ffff:127.0.0.1]/cb",
          "https://[::ffff:169.254.169.254]/cb",
          "https://224.0.0.1/cb",
          "https://255.255.255.255/cb"
        }) {
      assertTrue(url, refused(url));
    }
  }

  @Test
  public void publicAddressesAreAllowed() {
    assertEquals(Optional.empty(), OutboundUrls.problem("https://93.184.215.14/cb", false));
    assertEquals(Optional.empty(), OutboundUrls.problem("https://[2606:4700:4700::1111]/cb", false));
  }

  @Test
  public void onlyHttpUrlsWithAHostAndNoCredentials() {
    assertTrue(refused("ftp://93.184.215.14/cb"));
    assertTrue(refused("file:///etc/passwd"));
    assertTrue(refused("https:///cb"));
    assertTrue(refused("https://user:pass@93.184.215.14/cb"));
    assertTrue(refused("not a url"));
    assertTrue(refused("https://name.that.does.not.resolve.invalid/cb"));
  }

  @Test
  public void developmentCanAllowPrivateAddressesButNotOtherSchemes() {
    assertEquals(Optional.empty(), OutboundUrls.problem("http://127.0.0.1:8080/cb", true));
    assertTrue(OutboundUrls.problem("ftp://127.0.0.1/cb", true).isPresent());
  }

  @Test
  public void addressClassification() throws Exception {
    assertFalse(OutboundUrls.isPublic(InetAddress.getByName("100.127.255.255")));
    assertTrue(OutboundUrls.isPublic(InetAddress.getByName("100.128.0.1")));
    assertTrue(OutboundUrls.isPublic(InetAddress.getByName("172.32.0.1")));
    assertFalse(OutboundUrls.isPublic(InetAddress.getByName("192.0.0.8")));
  }
}
