package com.lattice.oidc.security;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * A fixed test PKI for Open Banking Brasil client-certificate checks, generated once with keytool
 * (100-year validity): {@link #ROOT} stands in for the OBB root, {@link #LEAF} is a client
 * certificate it issued, and {@link #STRANGER} is self-signed and chains to nothing.
 */
public final class ObbTestPki {
  private ObbTestPki() {}

  public static final String ROOT =
      """
      -----BEGIN CERTIFICATE-----
      MIIDFTCCAf2gAwIBAgIJAP7FlHsj4F7+MA0GCSqGSIb3DQEBDAUAMC8xFTATBgNV
      BAoTDExhdHRpY2UgVGVzdDEWMBQGA1UEAxMNVGVzdCBPQkIgUm9vdDAgFw0yNjEw
      MDMxNjQ4MDRaGA8yMTI2MDkwOTE2NDgwNFowLzEVMBMGA1UEChMMTGF0dGljZSBU
      ZXN0MRYwFAYDVQQDEw1UZXN0IE9CQiBSb290MIIBIjANBgkqhkiG9w0BAQEFAAOC
      AQ8AMIIBCgKCAQEA1CjP+q0A6KE668tclSOVj7McaNy3QL0nyfkIB5U36oWk4A89
      KWe3aw+zE6672Oi8dWCYL0hXingTXqhXFNY1Bf5DtGNPU5d/tOOOS5Hn/zxb7XVb
      c+2iRLOnITw8TO9kLujTeWQ2PfrNTwyjgvYGqOev7E1PsjTxLVz3fIwZ/7IF1QDn
      f0dl9Az/DFw+WTvaHikweG1WiXtO9ASOy1Kt2r7vGitZ1GqGJ5H/BysccWX/1LwM
      Aauz9Qyf5GSNz/r3Cnf4UHYruAip038v96HNjl8sOAhj46suDH/HgfaW+cDxwzxJ
      CVeSc9ShVtaAXex7PIfhgC4HvM2WAdd/Zx/AiQIDAQABozIwMDAdBgNVHQ4EFgQU
      56pLhW8n3dj8B3D39SdYIdgFQXIwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0B
      AQwFAAOCAQEAdiOSYIMDK5s/xZWSBBtMwz38EJa2TfBqaVcFzXwC5NEcBeRRFS5F
      qFzYjsSzuRM1T1sUFxq6RtW51LkaALEoOULxaXxqUvluo/CnBjDZstWjpUYSH0Jm
      zz3ph8QQ2rvnVrTDqX3H6cyNUEtS1gmRcMFFdcxhBBPjjOU8meSkttvtqh16YF6b
      1wVENPIq6AhVl2vO2m6J5wPyNzUJdowC/iGt1Ve+bpp4RDP14jJUFhwy18BLls8k
      qzdb+NLCx6AJUUsmypVhHr3Ue4RvZ9gTWSd3xyo8Uwf5B6E6BRlONmBUFoouUNNj
      cFnTXdvcWtGNa8XlalwGc7iJLSSpA3gDSQ==
      -----END CERTIFICATE-----
      """;

  public static final String LEAF =
      """
      -----BEGIN CERTIFICATE-----
      MIIDNjCCAh6gAwIBAgIIf3FVPFZsxwkwDQYJKoZIhvcNAQEMBQAwLzEVMBMGA1UE
      ChMMTGF0dGljZSBUZXN0MRYwFAYDVQQDEw1UZXN0IE9CQiBSb290MCAXDTI2MTAw
      MzE2NDgwNVoYDzIxMjYwOTA5MTY0ODA1WjAxMRkwFwYDVQQKExBMYXR0aWNlIFRl
      c3QgVFBQMRQwEgYDVQQDEwt0cHAuZXhhbXBsZTCCASIwDQYJKoZIhvcNAQEBBQAD
      ggEPADCCAQoCggEBAKdS71rd1gozR8iFVV7+WEvSieqsuaoirudm4C676J2AldB2
      ifD0uYnzYSC7H7srUOaVoDmFhE+b5CTjZdyBh7+59FA02QL/DlDm2UcO09HvqaMa
      HIh75v3nDZqvoI85oH9uhmuuTJ2iGCsugAP03tq5vyoGhN8yHbi0yGfcDBvTJogQ
      mQDHSNnT9ConRq34J+edxGoRNS40rSL+JlinO3pDsdFnePeAHgaVnIIigaGBSW1h
      wikTm2MJnmjFYj+FdaA7RicpLfe97s3oJRRu98Du0LA61jV12y49AbgS772U6vEK
      C4G+Q6o4A29JEhlEMFHnVkxEIBExeSt9SWwR5O8CAwEAAaNSMFAwHQYDVR0OBBYE
      FJfWrQDz7oG/FqbXbQ/EdkmWzmtSMA4GA1UdDwEB/wQEAwIFoDAfBgNVHSMEGDAW
      gBTnqkuFbyfd2PwHcPf1J1gh2AVBcjANBgkqhkiG9w0BAQwFAAOCAQEAyFC3YtiJ
      wXLwWJFVatYM13gun3a/bO0AHGahx5B7lkCj4MmRAgVrdrZk2Mrebl2psCmkbkSE
      8DLxgHjbQEWPvoLx/2aAIc/HpeRd3oavwqI/LHWPgwi+7Hg9KD1Al/OQhCE2R95v
      OghYv7XWA0kgejp1v+E8nSxBFOA2IBfSFrWoiGp6oXZtv95bwHCxVgUflWmF9VAf
      yxTZf2GOWXbhIUi1yCA22PPsJ3TyTPFQ8GyT3uwl0yZ4Byz7Rq0X8/TBblAU0sMu
      fsxJry18bOrDEglgYCGWfatvsr0LOVyCrP8YtnutJ6H6WO/3BRneg4ooGtXj68MP
      fPTL1qkSNZa4jA==
      -----END CERTIFICATE-----
      """;

  public static final String STRANGER =
      """
      -----BEGIN CERTIFICATE-----
      MIIC3DCCAcSgAwIBAgIJAPnHytun6YorMA0GCSqGSIb3DQEBDAUAMBsxGTAXBgNV
      BAMTEHN0cmFuZ2VyLmV4YW1wbGUwIBcNMjYxMDAzMTY0ODA1WhgPMjEyNjA5MDkx
      NjQ4MDVaMBsxGTAXBgNVBAMTEHN0cmFuZ2VyLmV4YW1wbGUwggEiMA0GCSqGSIb3
      DQEBAQUAA4IBDwAwggEKAoIBAQDIQYmWvcbd73kepXKUqBDBPytOpLJoBs3JWQrm
      izKATZlbyuLI+ua4hTEVk7I+ua7+4Sd8tYXHffEpDYFn3RqvJ81bfGAxuWDRsLa0
      xxVFzFzKKjBwsWquijN6k5nzHORHuZyGBylrfIQPZiiTntnD/PjA4wiNrnPY1LNr
      OG8Lcsb1H5x42Pa955o/+086ZyuiaRQnl5mmADBjQLPcd5g0nEOxE3Uy1VmvZfC6
      ocmEgCADL/xELxGNce+SVZdaHBtplrqNI9wEBVrJBc4knhEbBmbTeKiCAV8CegB5
      z/OFeoeVtf+6C4TYYAvh6tk6vUOCMKQ+zcfMVcBm1bvnVug9AgMBAAGjITAfMB0G
      A1UdDgQWBBTqeUhOns20wheTYJRAh2A5h/15CTANBgkqhkiG9w0BAQwFAAOCAQEA
      LkwuXnv1GDIsCYo6BHngY37flulouvrOqCUjToOTlMHj1ToOVaLPTLU/iHT5DwAW
      8LPiWk0sdiOJT1gBSAT83+F7b93UncdFiQq69iBM4GZYRi8uTs2I2eSzkzWk8FFn
      cBZ1mF9rJxUZf3ucdKtTUD7wAkUte6NdL+Mh5xZpPqiBvTiSqAxZvzlk79CG5ydT
      gqDcvNBuc7ENgj1IhulAD/ivt1odvGfy5BoAN6dWIAnCihUBhb1dajeGfczmhozg
      h2VlHqHI799vcqKjTuGSM+eYjo6foNXVRuGuomcx41bJQE7mPW5F6ahJsLAPh+Pl
      hxqnWBSqSM/Q2sIHB90eIQ==
      -----END CERTIFICATE-----
      """;

  /** Writes {@link #ROOT} to a temporary file, for {@code lattice.obb.root-certificates}. */
  public static String rootFile() {
    try {
      Path file = Files.createTempFile("obb-root", ".pem");
      file.toFile().deleteOnExit();
      Files.writeString(file, ROOT);
      return file.toString();
    } catch (IOException e) {
      throw new UncheckedIOException(e);
    }
  }
}
