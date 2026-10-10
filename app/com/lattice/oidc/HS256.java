package com.lattice.oidc;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Base64;

public final class HS256 {

    private static final Base64.Encoder B64URL = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder B64URL_DEC = Base64.getUrlDecoder();

    /** RFC 7515 §5.1: signs and returns the compact JWS. */
    public static String sign(String headerJson, byte[] payload, byte[] key) throws Exception {
        // RFC 7518 §3.2: key MUST be at least as long as the hash output
        if (key.length < 32) throw new IllegalArgumentException("HS256 key must be >= 256 bits");

        String signingInput = B64URL.encodeToString(headerJson.getBytes(StandardCharsets.UTF_8))
                + "." + B64URL.encodeToString(payload);

        byte[] sig = hmacSha256(key, signingInput.getBytes(StandardCharsets.US_ASCII));
        return signingInput + "." + B64URL.encodeToString(sig);
    }

    /** RFC 7515 §5.2: verifies a compact JWS. */
    public static boolean verify(String jws, byte[] key) throws Exception {
        int last = jws.lastIndexOf('.');
        if (last < 0 || jws.indexOf('.') == last) return false;  // need exactly header.payload.sig

        byte[] signingInput = jws.substring(0, last).getBytes(StandardCharsets.US_ASCII);
        byte[] expected = hmacSha256(key, signingInput);
        byte[] actual = B64URL_DEC.decode(jws.substring(last + 1));

        return MessageDigest.isEqual(expected, actual);           // constant-time compare
    }

    /** RFC 2104 HMAC with H = SHA-256, via the JCA. */
    static byte[] hmacSha256(byte[] key, byte[] text) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(key, "HmacSHA256"));
        return mac.doFinal(text);
    }

    /** RFC 2104 spelled out, for illustration: H((K' ^ opad) || H((K' ^ ipad) || text)). */
    static byte[] hmacSha256Manual(byte[] key, byte[] text) throws Exception {
        final int B = 64;                                         // SHA-256 block size
        MessageDigest sha = MessageDigest.getInstance("SHA-256");

        if (key.length > B) key = sha.digest(key);                // long keys are hashed first
        byte[] k = Arrays.copyOf(key, B);                         // then zero-padded to one block

        byte[] ipad = new byte[B], opad = new byte[B];
        for (int i = 0; i < B; i++) {
            ipad[i] = (byte) (k[i] ^ 0x36);
            opad[i] = (byte) (k[i] ^ 0x5c);
        }

        sha.update(ipad);
        sha.update(text);
        byte[] inner = sha.digest();

        sha.update(opad);
        sha.update(inner);
        return sha.digest();                                      // 32 bytes = JWS Signature
    }
}

