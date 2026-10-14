package com.lattice.oidc.security;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import java.text.ParseException;
import java.util.List;

/**
 * Ready-made keys for tests and sample setups: one for each kind a client or server registers.
 *
 * <p><b>Test keys only.</b> The private halves are published here, so anything signed or encrypted
 * with them proves nothing. Never register one of them with a real service or use it outside tests.
 *
 * <p>The public JWKs (what a client's {@code jwks} would hold) come from {@link #publicSet()}. The
 * {@code kid}s are fixed, and are not the keys' thumbprints.
 */
public final class TestJwks {

  /** RSA, for encrypting to a client: {@code use=enc}, {@code alg=RSA-OAEP}. */
  public static final String RSA_ENCRYPTION =
      """
      {
        "kty": "RSA", "use": "enc", "alg": "RSA-OAEP",
        "kid": "RgwLUNTZeDzIZ2QP7cYkxwGY3jceRv4w4cG-N96Pj0U",
        "e": "AQAB",
        "n": "nnbKx4g52gjXMK-8HL99pspa9UsQhGv11TbhIERUK4qGEFe9jg79uKXBBmS9a3kptrE02GrfPo1bWPUDvXtgF-N35DNApLOYqiHKZwpIvu_LUfh78LMe9s2JIglXMl7OCaLSe3qYT7JYrfXtEISJkfnjfxfV1VHSWMg-mMWhA1CwsOonE281DGnAlgMFu0UjO4Lxv68AemuK307EgnAJSSWjLPm0PoEdPP3twXMuNTc_KuWbV3fTGi-ex0jAF-BxcZsvn6RNQxUXDIOs-z2dTapc2WT63zbAAoryovZilqyst98Pr_-3CmfxTvwwoJou6BsoAFqVVIQ_-f8yS9D5vuyos_-g41U",
        "d": "CKluUikpyGJH_lBM1GF0k9kRzxYIVBoL-QNOm6iV1T91g-UtO7D-wMjGsVEbuDPfn4M2OUeLkRbBpy4qwyvAR-4A0AeBLBTpGRD5yFdxPIaiXYZbTVVChwkbIDIp2FtYSyyMRtWfsmje8hC0TFKCVpQLPGzoHQijmoNvmy2KV0JiNiQabF1pFSVCwos3xQDoF2UX_hbGIn3ceau9itHydYC2ZSzLnUCDXIDVW-0e7ehl5SOuTat3XPBOdb_-E4ULISm0QU4BpqKyvOpYVsS1kDiTFhnaIWTAsi_IvoK6DfkhxvBUB44JNHBNiHUgEih5yJL-oWdzlqvmJ_e_Rcw5ZPpSaE7gOQE",
        "p": "Db81T1xk17TjQXR0bNHuhaA4Bs8Q4rrLMuJr7DxCmGfLfZ-kwbGgfW8zjBdyH8l7PXGu6a2eJFHaPRHnU6YEFiOOO5YJJe8fToX6b6W4-9LyJLWu-57Zavqjm6ExW0sZW_AxJOcp_ZscpZrpBEAxtE2Ekf7XchK9kHyQT2fNB_GeuxsV",
        "q": "C4b51eDsElE_zo0iDZkcypsui261CNcOyPfIqUAEeDvjhuqZ5uTMJJbFHEQrU7k_n_NtOVZLuhpzyeB4js8s2oa3H5Cs2N6GCHs86eQy-5iwCfpyAzVsYjbbIjB-7s1z21jx4-E_GO1yvYye2k4yEPs4jzNQjzeQAiwwW73hz06vd7dB",
        "dp": "A4EGlKkHZ1hLSQbnGknUk6kIPuwO8MwOOXUvbzLZAsIKQ4Yq19hwASkUKZRcWa_gwwO0QwonMjjO-RwUK-U4S3Bas-OFh27ROxG5iTXj1gSqBiNta-PMpZEnnObUjuGwoBe0XySxNlyQS8IVvSijwsKzlQcxYXlXannlyue5glnbTPQV",
        "dq": "CMXjYwnZ4V8A5ty27A55wSE13VyWX3H9iKo8h8N3I2LBGa93DilXzQkKXybqqr-0UrHbkOXCoJL9SMmUN2wpwO8Cc_2R70P8UnwosgHBY4ajhBSdrR99q4oAYRbzpB-ta2VYQ4zsjrY4u1ZIl_EnXZE1TJdLWpR4_45OB6SONU63cK-B",
        "qi": "CfDynGTxiW96vMCi3kdt3R3E43YYqQcGftogSjBUetkl4_n_TsXMfVhi0tNgvH4a1fNwHAWeSL0mi3mLgyuKF78cpHcql7L7yQTa9dIIT7LqRvCvin-JumfEG0Ege1KtC2t2viO8Nmprzfq2y6T8stYxxmR6sE9WQozYOH84DirQ7CKH"
      }
      """;

  /** RSA, for signing: {@code use=sig}, {@code alg=RS256}. */
  public static final String RSA_SIGNING =
      """
      {
        "kty": "RSA", "use": "sig", "alg": "RS256",
        "kid": "pMzEXaWZmIx2iTZbreBgGNjFTugK6LyDlOe5-dCZrqw",
        "e": "AQAB",
        "n": "ssdQGA8KTLbi5RhqBT_NKy5anrHB9hLUBLpmhbz1OLO4lE5qt_PJWmCFwTL6GBg862v--2p6cgPbYKVGrLtHiKzLynO8_096lwox4ZOLWri6afzFGRJskGiVMkuEQkcs1iz4MDZPiYbHXWN-cp8s1dB13mzufxod4P_qxW1eyBLPQHZSYI59nduQKUzOjYyGJdrTM249oIBeYPXUD6o0gtOLE3eRy2nyWZ3TVx3NnC0wVe1ui-5LWWJiZVbqe_Kknog5JDZekDTxLbSELHNYbPDO8sNNfuAxLPRd8wW9WVuNNBXYZPBO7QOE5boyYqUMuG6mz4c_nuctsx4ctjk6SYwkEUC6eQ",
        "d": "BKvL05puVMt2ftvgxpsAe6oDY3VrhvK-Ur1NY8h9yRR7tHb0DN20G3C9g0BsuRJxDQmjqOKtqQBMIWilbGqcQjLu7tmP95prro9Cobfe1-j5sz6P0R7icpzOQSPTTylYP47_O8CU2sKzFM_pBDT_0TpYH2P4kJ5DEkI9hRkIH_F13s5CvrVE6sJk2N30b7uQcfb89uBUnlStMSihZcj1r17QLe5JJ-WRgyLtYHPsXpnLje5f_sbh8GsbuYErocDOmiXp71nS_cwHFf6cFcC6Nrx_kHGpn_6F9Z3NEJ8qAgMXXuSXWnxX3vqJZtOVxvLawppLdb7e_hpgXtY4NpfjMPLD_KFbcQ",
        "p": "519AksGDYbM150b2SxnNKKYTMiALyz6Nc8ya1BR4ppMc1KSyyswjnif2qlY_gfxkrU5MtjKHy_6lNpA8nIk96eDkQBQMFDjPPTk-PaaaHMgfseKoFZXv9CTF5dMgPhiatXURkr8xucrXZ53V8VUIqcwrk9OuSkhUOEnLOzBF3qTtog0",
        "q": "xc7rZph5IZChjCzSgPxKbNPT0dgR-UUefOePblXclFsbvC1Vt3gVHc4HxMIkLUT2jSQVlwziCpLQOyIdVdTtNM-kGHY5-U8kQZBDnIY-oXsJwiJAfKWODdj6uhh7MILksvKBvYa2k6J81wxG5ySmBC7p8B7wW6-SXn8Nf8vJy1G2Gx0",
        "dp": "ZC3B78kJ8ct-k10OVwYc5nTB6volISM8a98zSpByjO01lnyZTWWGJnx3ONmPNeDqVn-Ih3rpgVIIhs987uodfJ57NaN4d2kBkiiu4lK4d63Oy16wGGiLNNKXPSNk2n4cvmSp7zgJd8Bz89FLSOrgjWRxmdgVpuQaUyTgcgg8uGIA4iE",
        "dq": "RaMy_EtxWX-xX8fn08D98pIgYB_RNBBBS3e55v4TSadJfFX5dz2vMW73DS3LzqQYqFerwiGm8lH9PNQlv7HWUGFJQ9NbVYmnGe3P36rjIbZPGSk1yqv99qIMorc7pzhtixIU2sQyQodRq-OGkpk0WQSrFv3NYHnO7bWM6xCzWgDKO4E",
        "qi": "4CSKRs_ampdPW6oBFNNWj_ywFvLAF7wZdYG2iDsj4MmITc_U8aRkG7sBZh_Is5HcB6osHXG51mY97bIh1YVa1PrTeTR15dohaaSlT6de75lmXXyCxTBwxW9jEsgzPvDwig8AcpJ2vhVGlWwUWp2E64ygSHC0dzBzvBelKOB4pd8VJzc"
      }
      """;

  /** EC P-256, for signing: {@code alg=ES256}. */
  public static final String EC_P256_SIGNING =
      """
      {
        "kty": "EC", "use": "sig", "crv": "P-256", "alg": "ES256",
        "kid": "c59wKVm3-b8qClEyLcBsKaqRX2EXB3JmOipwIuFy02Y",
        "x": "C45A0I1AvGkh9U-UphWrMo050JGFJAXoNu9qruB9-3c",
        "y": "ntJJL_hrfAbL0qbxXqHH5oCn0N8PL3tw14ZUlpooGUg",
        "d": "cqp6J8NcgkfF6MuuTsWgTA49yikmaMMX1WdKBQrf-DE"
      }
      """;

  /** EC P-384, for encryption: {@code alg=ECDH-ES}. */
  public static final String EC_P384_ECDH_ES =
      """
      {
        "kty": "EC", "use": "enc", "crv": "P-384", "alg": "ECDH-ES",
        "kid": "sZbXuFSsyRaJnzKj_5QTCbZSUivtTvjfagjT-DxME-I",
        "x": "SSKzs5PcHGHmLQpuQJ-xiLdQJZe8037a9_L5HcUsd9sht_zWcqSSeyHOjXiEVE-v",
        "y": "GZw6E296u5hPsYihADsx244ImmP_AMpbPkFil8VASPyPx9WlK2PDzF8YzacR55_E",
        "d": "K_I2CkioiLcbMsHRIyxQQpChHWJmv89JJfZ-AGszq0_NGG72esB9VucEhGH8C7ap"
      }
      """;

  /** EC P-384, for encryption: {@code alg=ECDH-ES+A128KW}. */
  public static final String EC_P384_ECDH_ES_A128KW =
      """
      {
        "kty": "EC", "use": "enc", "crv": "P-384", "alg": "ECDH-ES+A128KW",
        "kid": "eCxPnByHLbOonSZFs6GGdVvOfjY3TGLCksABrFuyMSg",
        "x": "SySo_NmWBe7uWddE8lx3FakqFN-rgfg-bWt-7XQwLndjFWE46FOt9807lXLHApt5",
        "y": "GTVZRtvxlmXZpdAF4ouxARcWxib2gXQ9yGRDxqxJC41JyDt6CcJP-4C419H-E1o4",
        "d": "UFeX5SwualsR4MnZ2Q58N5D1SBe26idyHtospa_hdvD8oJcKRbQJGiFCpU0IjPuA"
      }
      """;

  /** EC P-384, for encryption: {@code alg=ECDH-ES+A192KW}. */
  public static final String EC_P384_ECDH_ES_A192KW =
      """
      {
        "kty": "EC", "use": "enc", "crv": "P-384", "alg": "ECDH-ES+A192KW",
        "kid": "wb726uPp4AASkIJAKDKX8uKTuW6lEuuEp_s66suEyPw",
        "x": "zAISHMCM1oIxQeWvuCayb3Xx2S7zrvpOKn9pzF1QsyzV-dos6DGbrue-zGIQXygT",
        "y": "_nGEYG-DvO4wo6vjiZvv2ar_kAteVZcbSHlFA9-J4t9R-1DoKsMVT0VGjAOR2cHc",
        "d": "2-7DYdwqRt5b9xVpUAAo2ulLLvfDapYpC4xhocOP8xrWO8ABMfbMKW2j__hsSkR-"
      }
      """;

  /** EC P-521, for encryption: {@code alg=ECDH-ES+A192KW}. */
  public static final String EC_P521_ECDH_ES_A192KW =
      """
      {
        "kty": "EC", "use": "enc", "crv": "P-521", "alg": "ECDH-ES+A192KW",
        "kid": "7fxfFtqezWwRCsYqMb2rwthJ1iqoSE8D-JYuEaLeqJA",
        "x": "AABtKevVddt8q3ydAXWy1GMuDGQzsWv_a5mxU4Qr78Um67En2trHab_fENwxeNUJZPiGDF0euzcz2OuDtHwIdTzx",
        "y": "AdocSp5lHa1tWSk0bjyHCgoTeqz8PRkIqVqmky2RnhvwfLvXG3NCLy6EZv1VKc24o1iODh_2olJaiXZkbjUb5WrJ",
        "d": "ADoEA0dWKSlMx9MHgLqhEhE8kLyHNsl8M0NRCMSBO5o2BC7bNuPRc87bVubdOJSSWNGDP0ijrZfv__Kx63E7JvVl"
      }
      """;

  /** All of the above, as JSON text. */
  public static final List<String> ALL =
      List.of(
          RSA_ENCRYPTION,
          RSA_SIGNING,
          EC_P256_SIGNING,
          EC_P384_ECDH_ES,
          EC_P384_ECDH_ES_A128KW,
          EC_P384_ECDH_ES_A192KW,
          EC_P521_ECDH_ES_A192KW);

  private TestJwks() {}

  /** The key with its private half. */
  public static JWK parse(String json) {
    try {
      return JWK.parse(json);
    } catch (ParseException e) {
      throw new IllegalStateException("A test key does not parse: " + e.getMessage(), e);
    }
  }

  /** All the keys, private halves included. */
  public static JWKSet privateSet() {
    return new JWKSet(ALL.stream().map(TestJwks::parse).toList());
  }

  /** All the keys, public halves only: what a client registers as its {@code jwks}. */
  public static JWKSet publicSet() {
    return privateSet().toPublicJWKSet();
  }
}
