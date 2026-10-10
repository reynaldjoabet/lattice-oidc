package com.lattice.oidc;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.factories.DefaultJWSVerifierFactory;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

public final class DPoP {

    public static final JOSEObjectType DPOP_JWT = new JOSEObjectType("dpop+jwt");

    // ---------------------------------------------------------------- client side

    /**
     * Builds a DPoP proof (RFC 9449 §4.2).
     *
     * @param accessToken null for token-endpoint requests; set for resource requests (adds ath)
     * @param nonce       null unless the server sent a DPoP-Nonce
     */
    public static String createProof(ECKey key, String htm, URI htu,
                                     String accessToken, String nonce) throws JOSEException {
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .type(DPOP_JWT)
                .jwk(key.toPublicJWK())                       // public part only
                .build();

        JWTClaimsSet.Builder claims = new JWTClaimsSet.Builder()
                .jwtID(Base64URL.encode(randomBytes(16)).toString())
                .claim("htm", htm)
                .claim("htu", stripQueryAndFragment(htu).toString())
                .issueTime(new Date());

        if (accessToken != null) claims.claim("ath", ath(accessToken));
        if (nonce != null)       claims.claim("nonce", nonce);

        SignedJWT jwt = new SignedJWT(header, claims.build());
        jwt.sign(new ECDSASigner(key));
        return jwt.serialize();
    }

    /** ath = BASE64URL(SHA-256(ASCII(access_token))), RFC 9449 §4.2. */
    public static String ath(String accessToken) {
        try {
            byte[] h = MessageDigest.getInstance("SHA-256")
                    .digest(accessToken.getBytes(StandardCharsets.US_ASCII));
            return Base64URL.encode(h).toString();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    // ---------------------------------------------------------------- server side

    public record Verified(JWK publicKey, Base64URL jkt, JWTClaimsSet claims) {}

    public static final class InvalidProof extends Exception {
        InvalidProof(String msg) { super(msg); }
    }

    private static final Set<JWSAlgorithm> ALLOWED =
            Set.of(JWSAlgorithm.ES256, JWSAlgorithm.ES384, JWSAlgorithm.PS256, JWSAlgorithm.EdDSA);
    private static final Duration IAT_WINDOW = Duration.ofSeconds(60);

    /** jti replay cache; use a shared store with TTL in production. */
    private final Map<String, Instant> seenJti = new ConcurrentHashMap<>();

    /**
     * Verifies a DPoP proof (RFC 9449 §4.3).
     *
     * @param accessToken   null at the token endpoint; the presented token at a resource server
     * @param expectedJkt   cnf.jkt from the access token (resource server), else null
     * @param expectedNonce the nonce this server issued, or null if nonces are not used
     */
    public Verified verify(List<String> dpopHeaders, String method, URI requestUri,
                           String accessToken, String expectedJkt, String expectedNonce)
            throws InvalidProof {

        // 1. exactly one DPoP header
        if (dpopHeaders == null || dpopHeaders.size() != 1) throw new InvalidProof("need exactly one DPoP header");

        // 2. well-formed JWS
        SignedJWT jwt;
        JWTClaimsSet c;
        try {
            jwt = SignedJWT.parse(dpopHeaders.get(0));
            c = jwt.getJWTClaimsSet();
        } catch (java.text.ParseException e) {
            throw new InvalidProof("malformed DPoP proof");
        }
        JWSHeader h = jwt.getHeader();

        // 3. typ, 4. asymmetric allowed alg (never none / HS*)
        if (!DPOP_JWT.equals(h.getType())) throw new InvalidProof("typ must be dpop+jwt");
        if (!ALLOWED.contains(h.getAlgorithm())) throw new InvalidProof("alg not allowed");

        // 5. jwk present and public only
        JWK jwk = h.getJWK();
        if (jwk == null || jwk.isPrivate()) throw new InvalidProof("jwk missing or contains private key");

        // 6. signature with the embedded key
        try {
            if (jwk instanceof OctetKeyPair okp) {
                // Nimbus's Ed25519Verifier needs Google Tink, which isn't on the classpath;
                // the JDK verifies Ed25519 itself (Java 15+).
                if (!JWSAlgorithm.EdDSA.equals(h.getAlgorithm()) || !verifyEd25519(jwt, okp))
                    throw new InvalidProof("bad signature");
            } else {
                JWSVerifier v = new DefaultJWSVerifierFactory().createJWSVerifier(h, toPublicKey(jwk));
                if (!jwt.verify(v)) throw new InvalidProof("bad signature");
            }
        } catch (JOSEException e) {
            throw new InvalidProof("cannot verify signature: " + e.getMessage());
        }

        // 7. required claims
        String jti = c.getJWTID();
        Object htm = c.getClaim("htm"), htu = c.getClaim("htu");
        Date iat = c.getIssueTime();
        if (jti == null || htm == null || htu == null || iat == null) throw new InvalidProof("missing claim");

        // 8. htm / htu match the actual request (htu compared without query + fragment)
        if (!method.equals(htm)) throw new InvalidProof("htm mismatch");
        if (!normalize(URI.create(htu.toString())).equals(normalize(requestUri)))
            throw new InvalidProof("htu mismatch");

        // 9. nonce
        if (expectedNonce != null && !expectedNonce.equals(c.getClaim("nonce")))
            throw new InvalidProof("use_dpop_nonce");

        // 10. freshness
        Instant now = Instant.now(), issued = iat.toInstant();
        if (issued.isBefore(now.minus(IAT_WINDOW)) || issued.isAfter(now.plus(IAT_WINDOW)))
            throw new InvalidProof("iat outside acceptable window");

        // 11. binding to the access token
        Base64URL jkt;
        try {
            jkt = jwk.computeThumbprint();                     // RFC 7638, SHA-256
        } catch (JOSEException e) {
            throw new InvalidProof("cannot compute thumbprint");
        }
        if (accessToken != null) {
            if (!MessageDigest.isEqual(ath(accessToken).getBytes(StandardCharsets.US_ASCII),
                    String.valueOf(c.getClaim("ath")).getBytes(StandardCharsets.US_ASCII)))
                throw new InvalidProof("ath mismatch");
            if (expectedJkt == null || !expectedJkt.equals(jkt.toString()))
                throw new InvalidProof("key does not match cnf.jkt");
        }

        // 12. replay (after all other checks, so junk can't fill the cache)
        seenJti.values().removeIf(t -> t.isBefore(now.minus(IAT_WINDOW.multipliedBy(2))));
        if (seenJti.putIfAbsent(jti, now) != null) throw new InvalidProof("jti replayed");

        return new Verified(jwk, jkt, c);
    }

    // ---------------------------------------------------------------- helpers

    /** The X.509 SubjectPublicKeyInfo prefix of an Ed25519 key (RFC 8410); the 32-byte key follows. */
    private static final byte[] ED25519_SPKI_PREFIX =
            {0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00};

    private static boolean verifyEd25519(SignedJWT jwt, OctetKeyPair okp) {
        byte[] x = okp.getDecodedX();
        if (!Curve.Ed25519.equals(okp.getCurve()) || x == null || x.length != 32) return false;
        byte[] spki = Arrays.copyOf(ED25519_SPKI_PREFIX, ED25519_SPKI_PREFIX.length + 32);
        System.arraycopy(x, 0, spki, ED25519_SPKI_PREFIX.length, 32);
        try {
            java.security.PublicKey key = java.security.KeyFactory.getInstance("Ed25519")
                    .generatePublic(new java.security.spec.X509EncodedKeySpec(spki));
            java.security.Signature signature = java.security.Signature.getInstance("Ed25519");
            signature.initVerify(key);
            signature.update(jwt.getSigningInput());
            return signature.verify(jwt.getSignature().decode());
        } catch (java.security.GeneralSecurityException e) {
            return false;
        }
    }

    private static java.security.Key toPublicKey(JWK jwk) throws JOSEException {
        if (jwk instanceof ECKey ec) return ec.toECPublicKey();
        if (jwk instanceof RSAKey rsa) return rsa.toRSAPublicKey();
        throw new JOSEException("unsupported key type " + jwk.getKeyType());
    }

    private static URI stripQueryAndFragment(URI u) {
        return URI.create(u.getScheme() + "://" + u.getRawAuthority() + (u.getRawPath() == null ? "" : u.getRawPath()));
    }

    /** RFC 9449 §4.3: compare htu without query/fragment, with scheme/host lower-cased. */
    private static URI normalize(URI u) {
        URI s = stripQueryAndFragment(u.normalize());
        int port = s.getPort();
        if (("https".equalsIgnoreCase(s.getScheme()) && port == 443)
                || ("http".equalsIgnoreCase(s.getScheme()) && port == 80)) port = -1;
        String path = s.getRawPath() == null || s.getRawPath().isEmpty() ? "/" : s.getRawPath();
        return URI.create(s.getScheme().toLowerCase(Locale.ROOT) + "://" + s.getHost().toLowerCase(Locale.ROOT)
                + (port == -1 ? "" : ":" + port) + path);
    }

    private static byte[] randomBytes(int n) {
        byte[] b = new byte[n];
        new java.security.SecureRandom().nextBytes(b);
        return b;
    }
}
