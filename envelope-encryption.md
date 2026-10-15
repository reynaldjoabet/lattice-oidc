# Envelope encryption, KMS and JWE

Notes on envelope encryption with a KMS, and how JWE applies the same idea to tokens.

## Envelope encryption with a KMS

A KMS (Key Management Service) is a managed service that holds keys and performs operations with them, for example AWS KMS, Google Cloud KMS, Azure Key Vault or HashiCorp Vault Transit.
An HSM (Hardware Security Module) is tamper-resistant hardware that does the same thing. Most cloud KMSs run on HSMs.

Envelope encryption means encrypting your data with one key, then encrypting that key with another key. The encrypted data and its encrypted key are stored together

` the KEK never leaves the KMS. You don't download it. You send a DEK in and get it back encrypted, or send an encrypted DEK in and get it back decrypted. Wrapping a key this way is often called wrapping and unwrapping`

### Encrypting, step by step

1. Generate a fresh random DEK (e.g. 256-bit AES key)        ← locally, or ask the KMS for one
2. Encrypt the data with the DEK (AES-256-GCM)                ← locally, fast
3. Send the DEK to the KMS: "wrap this with KEK #k1"          ← small network call
   KMS returns: encrypted DEK
4. Store  { encrypted DEK, KEK id "k1", IV, ciphertext, auth tag }
5. Wipe the plaintext DEK from memory


### Decrypting, step by step

1. Read the envelope
2. Send encrypted_dek + kek_id to the KMS: "unwrap this"      ← KMS checks: is this caller allowed?
   KMS returns: plaintext DEK
3. Decrypt the ciphertext with the DEK locally (and verify the auth tag)
4. Wipe the DEK from memory
Step 2 is where access control happens. The KMS decides who may unwrap, logs every call, and can refuse. Someone who steals your database gets ciphertext and encrypted DEKs. Without permission to call the KMS, that's useless to them.

### Why not encrypt the data with the master key directly?
1. Performance and size limits
KMS calls go over the network, are rate-limited and cost money. Many accept only a few kilobytes per call; AWS KMS's `Encrypt` accepts at most 4 KB.

Direct: encrypting a 10 GB backup means sending all 10 GB through the KMS. That's impractical.
Envelope: the KMS only ever sees a 32-byte DEK. The 10 GB is encrypted locally with AES, at gigabytes per second.
2. The master key is never exposed
If the KEK ever had to sit in application memory, any memory dump, log or bug could leak the key for all your data. With envelope encryption, the application only holds a DEK briefly, and each DEK protects only its own piece of data.

3. A small blast radius
Use a separate DEK per file, row, tenant or backup. A leaked DEK exposes only that one item, not everything.

4. Cheap key rotation
Rotating the master key doesn't require re-encrypting the data:
```sh
Before:  encrypted_dek = wrap(KEK_v1, DEK)    ciphertext = AES(DEK, data)
Rotate:  encrypted_dek = wrap(KEK_v2, DEK)    ciphertext = unchanged
```
You re-wrap each 32-byte DEK, and terabytes of data stay untouched. Many KMSs make this even easier: they keep old key versions for decryption and use the newest for new encryptions, so old envelopes keep working.

Note the limit: this rotates the KEK. If you suspect a DEK leaked, you must re-encrypt the data under a new DEK.

5. Crypto-shredding: deleting by deleting keys
To destroy a tenant's data everywhere, including in backups and replicas you can't easily reach, delete their KEK or their DEKs. The ciphertext still exists but can never be decrypted again. This is a common approach for GDPR "right to erasure" in multi-tenant systems: one KEK per tenant.

6. Separation of duties
The people who can read the database (DBAs, backup operators) can't read the data, because they can't call the KMS. The people who manage the KMS can't read it either, because they don't have the ciphertext. Reading data requires both.

```java
// --- encrypt ---
GenerateDataKeyResponse dk = kms.generateDataKey(r -> r
        .keyId("alias/orders-kek")
        .keySpec(DataKeySpec.AES_256)
        .encryptionContext(Map.of("table", "orders", "row", "42")));

byte[] dek = dk.plaintext().asByteArray();          // use, then wipe
byte[] encryptedDek = dk.ciphertextBlob().asByteArray(); // store this

byte[] iv = new byte[12];
SecureRandom.getInstanceStrong().nextBytes(iv);
Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(dek, "AES"), new GCMParameterSpec(128, iv));
c.updateAAD("orders:42".getBytes(UTF_8));
byte[] ciphertext = c.doFinal(plaintext);
Arrays.fill(dek, (byte) 0);

store(encryptedDek, iv, ciphertext);                // the envelope

// --- decrypt ---
byte[] dek2 = kms.decrypt(r -> r
        .ciphertextBlob(SdkBytes.fromByteArray(encryptedDek))
        .encryptionContext(Map.of("table", "orders", "row", "42")))  // must match
        .plaintext().asByteArray();

Cipher d = Cipher.getInstance("AES/GCM/NoPadding");
d.init(Cipher.DECRYPT_MODE, new SecretKeySpec(dek2, "AES"), new GCMParameterSpec(128, iv));
d.updateAAD("orders:42".getBytes(UTF_8));
byte[] recovered = d.doFinal(ciphertext);           // throws if anything was tampered with
Arrays.fill(dek2, (byte) 0);
```

Option 1: same row, separate columns
The simplest layout: each encrypted row carries its own wrapped DEK.

```sql
CREATE TABLE patient_records (
    id              BIGINT PRIMARY KEY,
    patient_name    TEXT,          -- not sensitive, plaintext
    diagnosis_ct    BYTEA,         -- ciphertext (encrypted with the DEK)
    diagnosis_iv    BYTEA,         -- 12-byte nonce for AES-GCM
    encrypted_dek   BYTEA,         -- the DEK, wrapped by the KEK in the KMS
    kek_id          TEXT           -- which KMS key wrapped it, e.g. 'arn:aws:kms:...:key/abc'
);
```
- Pro: easy to understand, and each row has its own DEK. Con: a KMS call for every row you read, which is slow and costly for big queries.

Option 2: a separate key table (one DEK, many rows)
Instead of one DEK per row, use one DEK per tenant, per day, or per batch. Store the wrapped DEKs in their own table and reference them by ID:
```sql
CREATE TABLE data_keys (
    dek_id         UUID PRIMARY KEY,
    tenant_id      BIGINT,
    encrypted_dek  BYTEA,      -- wrapped by the KEK
    kek_id         TEXT,
    created_at     TIMESTAMP,
    retired_at     TIMESTAMP   -- stop using for new writes after this
);

CREATE TABLE patient_records (
    id            BIGINT PRIMARY KEY,
    tenant_id     BIGINT,
    dek_id        UUID REFERENCES data_keys(dek_id),
    diagnosis_ct  BYTEA,       -- iv || ciphertext || tag
);
```
To read 10,000 rows of tenant 7: unwrap tenant 7's DEK once, keep it in memory briefly, and decrypt all 10,000 rows locally.

Pros:
- Far fewer KMS calls.
- Crypto-shredding is easy: delete a tenant's rows in `data_keys` (or destroy their KEK) and all their data becomes unreadable, including copies in backups.
- DEK rotation is clean: mark the old DEK retired, create a new one, and re-encrypt rows over time.
- Con: a bigger blast radius per DEK. You must also keep the `data_keys` table safe from accidental deletion, because losing a row there loses data.


### Files and objects: in a header or in metadata
The same idea applies outside databases.

Inside the file, as a header:
```sh
backup-2026-10-15.enc
├── header: version, kek_id, encrypted_dek, iv
└── body:   AES-GCM ciphertext of the backup (gigabytes)
```
Beside the object, as metadata. This is what AWS S3 does with client-side encryption, and conceptually also with SSE-KMS:
```sh
s3://my-bucket/scan-42.pdf
  body:      ciphertext
  metadata:  x-amz-key-v2:   <encrypted DEK>
             x-amz-iv:       <iv>
             x-amz-wrap-alg: kms+context
```             
Kubernetes Secrets with a KMS provider work the same way. The value stored in etcd is a blob: prefix + wrapped DEK + ciphertext.

## JWE: envelope encryption for tokens

JWE (JSON Web Encryption) is envelope encryption, with standardized names and a standard format. You encrypt the **content key**, called the CEK, **with** the recipient's key, which plays the KEK's role. The KEK itself is never sent anywhere.

### Name mapping

| Envelope encryption | JWE name | Example |
|---|---|---|
| DEK | **CEK** (Content Encryption Key) | a random AES key, fresh for every token |
| KEK | the **recipient's key** | the recipient's RSA **public** key, or a shared AES key |
| Wrapped DEK | **JWE Encrypted Key** | the second part of the token |
| How the DEK is wrapped | **`alg`** header | `RSA-OAEP-256`, `A256KW`, `ECDH-ES+A256KW` |
| How the data is encrypted | **`enc`** header | `A256GCM`, `A128CBC-HS256` |
| AAD | the protected header | automatically bound to the ciphertext |

There are **two** algorithm fields because there are two encryption steps: `alg` wraps the key, `enc` encrypts the data. People often confuse them.

### A JWE is literally an envelope

The compact form has five base64url parts separated by dots:

```
eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMjU2R0NNIn0 .  ← 1. protected header
OKOawDo13gRp2ojaHV7LFpZcgV7T6DVZKTyKOMTYUmKoTCVJRgck .  ← 2. encrypted key (the wrapped CEK)
48V1_ALb6US04U3b                                     .  ← 3. IV
5eym8TW_c8SuK0ltJ3rpYIzOeDQz7TALvtu6UG9oMo4vpzs9tX_E .  ← 4. ciphertext
XFBoMYUZodetZdvTiFvSkQ                                  ← 5. authentication tag
```

The header decodes to:

```json
{ "alg": "RSA-OAEP-256", "enc": "A256GCM", "kid": "client-enc-key-1" }
```

This is the same envelope as the database blob above: **wrapped DEK, IV, ciphertext and tag, together in one value**. The header adds which algorithms and which key (`kid`) were used, playing the role of the version byte and `kek_id`.

### Encrypting a JWE

Example: an authorization server sending an encrypted ID token to a client that has registered an RSA public key.

```
1. Generate a random CEK (256-bit AES)                         ← the DEK
2. Encrypt the CEK with the client's RSA public key (RSA-OAEP)  ← "alg": wrap the DEK
   → part 2, the encrypted key
3. Generate a random IV                                         ← part 3
4. AES-256-GCM encrypt the payload with the CEK,
   using the header as AAD                                      ← "enc"
   → part 4 (ciphertext) and part 5 (tag)
5. Join the five parts with dots
```

### Decrypting a JWE

```
1. Read the header: alg = RSA-OAEP-256, enc = A256GCM, kid = client-enc-key-1
2. Decrypt part 2 with the private key for that kid  → CEK      ← "unwrap the DEK"
3. AES-GCM decrypt part 4 with the CEK, IV (part 3), header as AAD,
   and check the tag (part 5)                         → payload
```

The only differences from KMS-based envelope encryption:
- The KEK is usually an **asymmetric key pair**. Anyone with the public key can encrypt, and only the private-key holder can decrypt. With a KMS, both wrap and unwrap need a KMS call.
- The unwrap happens **wherever the private key lives**: in your app, or inside a KMS/HSM if you keep the private key there.

### The `alg` options: not all of them are envelopes

| `alg` | How the CEK is handled | Envelope? | Part 2 |
|---|---|---|---|
| `RSA-OAEP`, `RSA-OAEP-256` | random CEK, **encrypted** with the recipient's RSA public key | ✓ yes | wrapped CEK |
| `A128KW`, `A256KW` | random CEK, **wrapped** with a shared AES key (AES Key Wrap) | ✓ yes | wrapped CEK |
| `ECDH-ES+A256KW` | derive a temporary key with ECDH, then **wrap** the random CEK with it | ✓ yes | wrapped CEK |
| `ECDH-ES` | the CEK itself is **derived** with ECDH, nothing is wrapped | ✗ no | **empty** |
| `dir` | a shared key **is** the CEK | ✗ no | **empty** |
| `RSA1_5` | like RSA-OAEP but with old padding | yes, but **avoid it** (vulnerable to padding-oracle attacks; Lattice's `JoseAlgorithms` refuses it, see [Security building blocks](#security-building-blocks)) | wrapped CEK |

With `dir`, a JWE looks like `header..iv.ciphertext.tag`, with two dots together because part 2 is empty. There's no envelope, just ordinary authenticated encryption under a key both sides already share.

### Multiple recipients: the envelope's biggest win

The JSON form of JWE can address **several recipients**. The data is encrypted **once**, and the CEK is wrapped **once per recipient**:

```json
{
  "protected": "eyJlbmMiOiJBMjU2R0NNIn0",
  "recipients": [
    { "header": { "alg": "RSA-OAEP-256", "kid": "alice" }, "encrypted_key": "...CEK for Alice..." },
    { "header": { "alg": "ECDH-ES+A256KW", "kid": "bob" },   "encrypted_key": "...CEK for Bob..." }
  ],
  "iv": "...", "ciphertext": "...", "tag": "..."
}
```

This is how PGP email with several recipients works. Without an envelope, you'd have to encrypt the whole payload separately for each person.

### Where Keycloak uses JWE

Keycloak's implementation is in `core/src/main/java/org/keycloak/jose/jwe/`, and splits the same way as `alg` and `enc`:
- `alg/`: `RSAWrapperAlgorithmProvider` (wraps the CEK with RSA) and `DirectAlgorithmProvider` (`dir`)
- `enc/`: `AesGcmEncryptionProvider` and `AesCbcHmacShaEncryptionProvider`

It's used for:
- **Encrypted ID tokens and userinfo responses.** A client can set "ID token encryption key management algorithm" (`alg`) and "content encryption algorithm" (`enc`) in its advanced settings (`OIDCAdvancedConfigWrapper`). Keycloak then wraps the CEK with the **client's** public key, taken from its JWKS (`UserInfoEndpoint`, `DefaultTokenManager`).
- **Internal data that Keycloak itself reads back**, such as `RestartLoginCookie` and `CIBAAuthenticationRequest`. These go through `TokenUtil.jweDirectEncode`, i.e. `dir` with a realm key. Keycloak is both the sender and the recipient, so an envelope adds nothing there.

### JWS vs JWE

Most access tokens are **JWS**, meaning **signed**, not encrypted. Anyone can base64-decode them and read the claims. The signature only proves the issuer created them and that nobody changed them. JWE is for when the contents must be **secret** from anyone except the recipient. Some systems do both: sign first, then put the signed JWT inside a JWE.

### Summary

JWE is envelope encryption with standard names. A fresh **CEK** (the DEK) encrypts the payload, as set by `enc`. The CEK is wrapped with the **recipient's key**, which acts as the KEK, as set by `alg`. The wrapped CEK travels in the token's second part, next to the IV, ciphertext and tag. Only `dir` and plain `ECDH-ES` skip the envelope.
