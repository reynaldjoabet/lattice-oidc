# Design lessons from Nimbus JOSE+JWT's crypto package

Nimbus JOSE+JWT is the Java library behind most JWT handling on the JVM, Lattice's included. Its `com.nimbusds.jose.crypto` package (about 15,000 lines) implements every JWS and JWE algorithm. These notes pick out the designs worth reusing anywhere, not just for JOSE. Each has:

- **The pattern**, and why it matters.
- **What Nimbus does**, with the file under `src/main/java/com/nimbusds/jose/crypto/`.
- **A port:** a self-contained version in plain JDK code.

All the ports are in [docs/nimbus-crypto/Ports.java](docs/nimbus-crypto/Ports.java), with checks for each. Run them with `java docs/nimbus-crypto/Ports.java`; all 24 pass.

Read against Nimbus `d919f7bf` (2 April 2026).

## 1. Fail closed on what you don't understand

**The pattern.** A JOSE header can list parameters in `crit`, meaning "if you don't understand these, reject the token". A parser that ignores unknown fields, as most JSON parsers do, would silently skip a restriction the sender required. So anything unknown fails, unless the caller has explicitly said it handles that parameter itself.

**Nimbus** (`impl/CriticalHeaderParamsDeferral.java`): two sets, the parameters the library processes (`b64`) and those the application deferred to itself. Anything else fails. Every verifier and decrypter calls it before doing any cryptography.

**Port:**

```java
record CritPolicy(Set<String> understood, Set<String> deferred) {
  boolean passes(Set<String> critical) {
    if (critical == null) return true;
    for (String name : critical) {
      if (!understood.contains(name) && !deferred.contains(name)) return false;
    }
    return true;
  }
}
```

The default is safe, and opting out names exactly what you take responsibility for. The same idea applies to any versioned protocol or config format: an unknown *must-understand* field is an error, never a warning.

## 2. Make insecure behaviour a named, typed opt-in

**The pattern.** Some callers need unsafe settings, such as a legacy 1024-bit RSA key. A boolean (`allowWeakKeys = true`) is easy to pass by accident and hard to spot in review. A dedicated object whose name says what it does is neither.

**Nimbus** (`opts/AllowWeakRSAKey.java`, `opts/OptionUtils.java`): a singleton `AllowWeakRSAKey.getInstance()` passed in a set of options. Without it, keys under 2048 bits throw. Option classes implement marker interfaces (`JWSSignerOption`, `JWEDecrypterOption`), so an option is accepted only by the operations it applies to.

**Port**, with sealed interfaces, so the compiler rejects an option meant for a different operation:

```java
sealed interface SignerOption permits AllowWeakKey {}
sealed interface DecrypterOption permits AllowWeakKey, MaxInflatedLength {}

enum AllowWeakKey implements SignerOption, DecrypterOption { INSTANCE }
record MaxInflatedLength(int bytes) implements DecrypterOption { /* bytes > 0 */ }

static void ensureKeySize(int keyBits, Set<? extends SignerOption> options) {
  if (keyBits < 2048 && !options.contains(AllowWeakKey.INSTANCE)) {
    throw new IllegalArgumentException("The RSA key size must be at least 2048 bits");
  }
}
```

`grep AllowWeakKey` then finds every exception to the policy.

## 3. Make every failure look the same

**The pattern.** RSA with PKCS #1 v1.5 padding (JWE `RSA1_5`) is open to Bleichenbacher's "million message attack". If an attacker can tell "the padding was wrong" apart from "the padding was right but something later failed", they can decrypt a ciphertext by sending about a million variations of it. The difference can show as different errors, or as different timing. The defence is to make the two paths indistinguishable.

**Nimbus** (`RSADecrypter.java`, `impl/RSA1_5.java`):
1. **Before** decrypting, it generates a random content key.
2. If RSA decryption throws, or yields a key of the wrong length (signalled by `null`, not an exception), it continues with the random key.
3. The content decryption then fails at the authentication tag, exactly as it would for any tampered message.

**Port:**

```java
static byte[] unwrapOrRandom(KeyUnwrap unwrap, byte[] wrapped, int keyBytes, SecureRandom random) {
  byte[] fallback = new byte[keyBytes];
  random.nextBytes(fallback);           // drawn first: both paths do the same work
  try {
    byte[] key = unwrap.unwrap(wrapped);
    return key.length == keyBytes ? key : fallback;
  } catch (GeneralSecurityException e) {
    return fallback;
  }
}
```

The general lesson: when an error path exposes secret-dependent information, don't hide the error message, remove the branch. RSA-OAEP fixes this at the protocol level, which is why `RSA1_5` is deprecated.

**A bug in Nimbus here:** `RSADecrypter` stores the caught exception in `cekDecryptionException`, then sets that field to `null` two lines later, unconditionally. So the accessor meant for debugging never returns anything. It's harmless to security, but the debugging aid can't work.

## 4. Authenticate before you decrypt, over length-framed input

**The pattern.** Two rules for encrypt-then-MAC constructions:
- **Check the MAC before touching the ciphertext.** CBC padding errors are an oracle, like the RSA one above. If the MAC is checked first, a tampered ciphertext never reaches the padding check.
- **Frame what you MAC.** MAC-ing `aad || iv || ciphertext` alone is ambiguous: moving bytes from the end of `aad` to the start of `iv` gives the same input. Appending the length removes the ambiguity.

**Nimbus** (`impl/AESCBC.java`, `impl/AAD.java`): computes the HMAC over `aad || iv || ciphertext || AL`, where `AL` is the AAD's length in bits as 8 bytes (RFC 7516 §5.2.2.1). It compares the tags in constant time, and only then decrypts.

**Port:**

```java
mac.update(aad);
mac.update(iv);
mac.update(cipherText);
mac.update(ByteBuffer.allocate(8).putLong(Math.multiplyExact((long) aad.length, 8)).array());
byte[] expected = Arrays.copyOf(mac.doFinal(), 16);

if (!MessageDigest.isEqual(receivedTag, expected)) {
  throw new GeneralSecurityException("MAC check failed");   // before any padding is looked at
}
return cipher.doFinal(cipherText);
```

`Math.multiplyExact` matches Nimbus's `ByteUtils.safeBitLength`. Lengths in bits overflow an `int` at 256 MB, so the multiplication must be checked, not left to wrap.

## 5. Check a signature's shape before verifying it

**The pattern.** Don't rely on the crypto provider to reject structurally impossible input. In April 2022, CVE-2022-21449 ("psychic signatures") showed that Java 15 to 18 accepted an ECDSA signature with `r = s = 0` for **any** message and key. Every library that just called `Signature.verify` was exposed.

**Nimbus** (`impl/ECDSA.java`, `ensureLegalSignature`) checks, before the JDK sees the signature:

| Check | Why |
| --- | --- |
| Not all zero bytes | The CVE's exact input, rejected cheaply |
| Exact length for the algorithm (64 bytes for ES256) | A JWS signature is `r` and `s` concatenated, at fixed width |
| `r` and `s` not 0 | Both must be in `[1, n - 1]` (FIPS 186-5) |
| `r` and `s` less than the curve order `n` | Same |

**Port:**

```java
static boolean legalSignature(byte[] rs, ECParameterSpec curve) {
  BigInteger n = curve.getOrder();
  int half = (n.bitLength() + 7) / 8;
  if (rs.length != 2 * half) return false;
  BigInteger r = new BigInteger(1, Arrays.copyOfRange(rs, 0, half));
  BigInteger s = new BigInteger(1, Arrays.copyOfRange(rs, half, rs.length));
  return r.signum() > 0 && s.signum() > 0 && r.compareTo(n) < 0 && s.compareTo(n) < 0;
}
```

Nimbus's extra check, `r mod n != 0`, can't fail once `0 < r < n` holds, so the port leaves it out.

## 6. Bad input returns false; a broken setup throws

**The pattern.** A verifier has two very different kinds of failure:
- **The input is bad** (forged, malformed, tampered). That's normal, attacker-controlled and expected, so it gets a plain "no".
- **The verifier itself is broken** (an invalid key, a missing algorithm). That's a bug or a misconfiguration, and should be loud.

Mixing them up causes real bugs. If both throw, callers catch everything, and a misconfigured verifier quietly rejects every token. If both return `false`, you can't tell an attack from an outage.

**Nimbus** (`ECDSAVerifier.verify`): an illegal signature, failed DER transcoding or `SignatureException` returns `false`. An unsupported algorithm or an `InvalidKeyException` ("Invalid EC public key") throws `JOSEException`. The `crit` check (section 1) also returns `false`, because the header is input.

This is worth copying anywhere a function judges untrusted input.

## 7. Validate untrusted public keys

**The pattern.** In ECDH, the other party sends a public point, which is then multiplied by your private key. If the point isn't on your curve, it may be on a different, weaker curve with small subgroups. The result then leaks your private key a few bits at a time: the **invalid curve attack**. The point must satisfy the curve equation from [modular-arithmetic.md](modular-arithmetic.md#elliptic-curves-a-group-made-of-points), $y^2 \equiv x^3 + ax + b \pmod{p}$.

**Nimbus** (`utils/ECChecks.java`): checks the equation for the sender's ephemeral key in `ECDHDecrypter`, for the public key in `ECDSAVerifier`, and in ECDH-1PU.

**A gap:** it checks only the equation, not that the coordinates are field elements, from 0 to $p - 1$. Since $(x + p)^3 \equiv x^3 \pmod{p}$, the point $(x + p, y)$ passes too. In practice the JDK's own key validation catches this, but the check isn't complete by itself. The port adds the range and the point at infinity:

```java
static boolean onCurve(ECPoint point, ECParameterSpec spec) {
  if (point.equals(ECPoint.POINT_INFINITY)) return false;
  BigInteger p = ((ECFieldFp) spec.getCurve().getField()).getP();
  BigInteger x = point.getAffineX(), y = point.getAffineY();
  if (x.signum() < 0 || x.compareTo(p) >= 0 || y.signum() < 0 || y.compareTo(p) >= 0) return false;
  BigInteger left = y.multiply(y).mod(p);
  BigInteger right = x.pow(3).add(spec.getCurve().getA().multiply(x)).add(spec.getCurve().getB()).mod(p);
  return left.equals(right);
}
```

The full check in NIST SP 800-56A §5.6.2.3.3 also requires $n \cdot Q = \mathcal{O}$. For the NIST prime curves, whose cofactor is 1, every point on the curve passes that automatically.

## 8. Bound the work an attacker can make you do

**The pattern.** Some header values directly set how much work the receiver does. Every one of them needs a ceiling.

**Nimbus** has two:
- **PBES2 iteration count** (`PasswordBasedDecrypter.java`): the `p2c` header sets how many PBKDF2 rounds to run. A token with `p2c` set to two billion would occupy a CPU for minutes. Nimbus refuses more than 1,000,000. This was CVE-2023-52428.
- **Decompression** (`JWEObject.MAX_COMPRESSED_CIPHER_TEXT_LENGTH`, `opts/MaxCompressedCipherTextLength.java`): JWE can deflate the plaintext (`"zip": "DEF"`). Nimbus limits compressed ciphertext to 100,000 bytes.

**A gap in the second one:** it limits the input, but a decompression bomb is about the output. `util/DeflateUtils.decompress` inflates until the stream ends. DEFLATE's maximum ratio is about 1,032:1, and the check in `Ports.java` shows 10 MB of zeros compressing to 9,732 bytes, well under the limit. So one token can make Nimbus allocate about 100 MB. Anyone with the server's public key can create such a token, because public-key JWE needs no secret to encrypt. The port caps the output instead:

```java
static byte[] inflate(byte[] compressed, int maxBytes) throws DataFormatException {
  Inflater inflater = new Inflater(true);        // raw DEFLATE, as JWE uses
  try {
    inflater.setInput(compressed);
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    byte[] buffer = new byte[8192];
    while (!inflater.finished()) {
      int n = inflater.inflate(buffer);
      if (n == 0 && (inflater.needsInput() || inflater.needsDictionary())) {
        throw new DataFormatException("Truncated or invalid DEFLATE data");
      }
      if (out.size() + n > maxBytes) {
        throw new DataFormatException("Inflated data exceeds " + maxBytes + " bytes");
      }
      out.write(buffer, 0, n);
    }
    return out.toByteArray();
  } finally {
    inflater.end();
  }
}
```

The same rule applies to anything an attacker sizes: request bodies, JSON nesting depth, regex input, `Argon2` parameters taken from a stored hash, page sizes in an API.

## 9. Accept exact AEAD parameters, not "valid" ones

**The pattern.** AES-GCM *permits* IVs of any length and tags from 32 to 128 bits. Permitted isn't safe:
- **A short tag is easier to forge.** With a 32-bit tag, a forgery succeeds about once in 4 billion tries, and gets easier with message length.
- **A non-96-bit IV is hashed into the counter.** That loses the simple uniqueness argument the 96-bit form has.

**Nimbus** (`impl/AESGCM.java`, `validate`): when decrypting, the IV must be exactly 96 bits and the tag exactly 128, or it throws. Callers can't opt into weaker settings at all.

**Port:**

```java
if (iv.length != 12 || tagBits != 128) {
  throw new GeneralSecurityException("IV must be 96 bits and the tag 128 bits");
}
```

Lattice's `SecretCipher` already does the encrypting side right: `new GCMParameterSpec(128, nonce)`.

## 10. Let the key decide what an object may do

**The pattern.** Validate a key when the object is built, not at first use, and derive the object's capabilities from it.

**Nimbus** (`impl/MACProvider.java`):
1. **The constructor rejects** secrets under 256 bits with `KeyLengthException`.
2. **The supported algorithms come from the key's length.** A 384-bit secret supports HS256 and HS384, but not HS512, because RFC 7518 §3.2 requires a key at least as long as the hash.
3. **Signing re-checks** the key against the specific algorithm.

**Port:**

```java
record MacSigner(byte[] secret, Set<Hmac> algorithms) {
  MacSigner {
    int bits = secret.length * 8;
    if (bits < 256) throw new IllegalArgumentException("The secret must be at least 256 bits");
    secret = secret.clone();
    algorithms = EnumSet.noneOf(Hmac.class);
    for (Hmac alg : Hmac.values()) if (bits >= alg.minKeyBits) algorithms.add(alg);
    algorithms = Set.copyOf(algorithms);
  }
}
```

A badly configured key then fails at startup, with a clear message, not on the first request in production.

## 11. Report what the provider actually did

**The pattern.** When a pluggable component may override your input, return what it really used rather than assuming.

**Nimbus** (`impl/AESGCM.java`): `encrypt` takes the IV in a `Container<byte[]>`, an in/out parameter. After encrypting, it reads the parameters back from the cipher and stores the IV actually used. FIPS-mode providers may refuse a caller-supplied GCM IV and generate their own, and a JWE carrying the wrong IV could never be decrypted.

**Port:**

```java
cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv.value));
cipher.updateAAD(aad);
byte[] out = cipher.doFinal(plainText);
iv.value = cipher.getParameters().getParameterSpec(GCMParameterSpec.class).getIV();
```

## 12. Compare secrets in constant time, and mind the argument order

**The pattern.** `Arrays.equals` stops at the first difference, so its timing tells an attacker how many leading bytes they got right. MACs, tokens and API keys must be compared in time that doesn't depend on where they differ.

**Nimbus** (`utils/ConstantTimeUtils.areEqual`): XORs every byte pair into an accumulator. But it returns `false` **early** when the lengths differ, which reveals the secret's length.

**The JDK does better.** `MessageDigest.isEqual` (JDK 25 source) never returns early. It folds the length difference into the result, and loops over the first argument's length, reading the second with a branch-free index:

```java
int result = lenA - lenB;
for (int i = 0; i < lenA; i++) {
  int indexB = ((i - lenB) >>> 31) * i;   // i while i < lenB, else 0
  result |= digesta[i] ^ digestb[indexB];
}
return result == 0;
```

Its running time depends only on `lenA`. So **pass the attacker's value first**: then the timing reveals only something the attacker already knows.

**In Lattice:** `MessageDigest.isEqual` is used everywhere, but two calls put the secret first, so the timing reveals the secret's length:
- **[IntrospectionController.java:100](app/com/lattice/oidc/controllers/IntrospectionController.java#L100):** the resource server's secret.
- **[MetricsController.java:37](app/com/lattice/oidc/controllers/MetricsController.java#L37):** the metrics token.

The risk is low: both secrets are long and random, so knowing the length doesn't help guess them. The fix is to swap the arguments.

## 13. Separate domains

**The pattern.** When the same secret could feed different uses, mix the use into the derivation, so a value derived for one purpose is useless for another.

**Nimbus** (`impl/PBKDF2.formatSalt`): the PBKDF2 salt is `UTF8(alg) || 0x00 || salt`, as RFC 7518 §4.8.1.1 requires. A key derived for `PBES2-HS256+A128KW` can never equal one derived from the same password for `PBES2-HS512+A256KW`. The `0x00` separator stops one algorithm name from being a prefix of another. It also enforces a minimum salt of 8 bytes.

**Port:**

```java
static byte[] saltFor(String alg, byte[] salt) {
  if (salt.length < 8) throw new IllegalArgumentException("The salt must be at least 8 bytes");
  byte[] name = alg.getBytes(StandardCharsets.UTF_8);
  return ByteBuffer.allocate(name.length + 1 + salt.length).put(name).put((byte) 0).put(salt).array();
}
```

Lattice's pairwise `sub` is the same idea: an HMAC keyed per deployment, over the sector and the user, so identifiers from one sector can't be linked to another (see the README's [Pairwise sub](README.md#pairwise-sub-a-keyed-hash-instead-of-plain-concatenation)).

## 14. Error messages that say what would work

**Nimbus** (`impl/AlgorithmSupportMessage.java`): every "unsupported" error lists the alternatives, for example `Unsupported JWS algorithm HS256, must be ES256, ES384 or ES512`. A tiny helper builds the list with commas and a final "or". It costs nothing, and turns a support ticket into a one-line fix.

## Summary

| # | Pattern | Nimbus file | Gap found |
| --: | --- | --- | --- |
| 1 | Fail closed on unknown critical parameters | `impl/CriticalHeaderParamsDeferral` | |
| 2 | Insecure behaviour as a named, typed opt-in | `opts/AllowWeakRSAKey` | |
| 3 | Indistinguishable failures (Bleichenbacher) | `RSADecrypter`, `impl/RSA1_5` | Debug exception always `null` |
| 4 | MAC before decrypting; length-framed input | `impl/AESCBC`, `impl/AAD` | |
| 5 | Signature shape checked before verifying | `impl/ECDSA` | |
| 6 | False for bad input, throw for broken setup | `ECDSAVerifier` | |
| 7 | Untrusted points checked against the curve | `utils/ECChecks` | No coordinate range check |
| 8 | Ceilings on attacker-sized work | `PasswordBasedDecrypter`, `JWEObject` | Bomb limit on input, not output |
| 9 | Exact AEAD IV and tag sizes | `impl/AESGCM` | |
| 10 | Key validated at construction, capabilities from the key | `impl/MACProvider` | |
| 11 | Report the IV the provider used | `impl/AESGCM` | |
| 12 | Constant-time comparison | `utils/ConstantTimeUtils` | Early return leaks length |
| 13 | Domain separation | `impl/PBKDF2` | |
| 14 | Errors that list alternatives | `impl/AlgorithmSupportMessage` | |
