# A02 Cryptographic Failures

> Mostly about *not* implementing your own crypto. The hard part is choosing the right primitives, managing keys, and never logging the wrong thing.

## Common bugs

| Bug | Why bad |
|---|---|
| Storing passwords with MD5 / SHA1 / SHA256 | Designed to be fast; attackers crack them at billions per second on a GPU. Use bcrypt / scrypt / Argon2. |
| Symmetric crypto with ECB mode | Patterns leak through — see the [ECB penguin](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#/media/File:Tux_ECB.png). Use AES-GCM. |
| Hard-coded keys in config | Source-control archeology + leaked CI logs == leaked keys. Use a secrets manager. |
| TLS 1.0/1.1 still enabled | Both deprecated. TLS 1.2+ only, prefer 1.3. |
| Encrypting then signing in the wrong order | Encrypt-then-MAC is the safe order. AEAD modes (AES-GCM, ChaCha20-Poly1305) do this for you. |
| Logging the entire request body | Tokens, passwords, PII end up in log retention. Redact at the boundary. |

## Field-level encryption pattern

For PII columns (email, phone, ssn_last4, etc.), encrypt at the column level — not just at the disk level:

```ts
import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';

const KEY = await loadKeyFromVault();   // 32 bytes
const ALG = 'aes-256-gcm';

export function encryptField(plaintext: string): string {
  const iv = randomBytes(12);
  const cipher = createCipheriv(ALG, KEY, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  // store as iv || tag || ciphertext, base64-encoded
  return Buffer.concat([iv, tag, ciphertext]).toString('base64');
}

export function decryptField(stored: string): string {
  const buf = Buffer.from(stored, 'base64');
  const iv = buf.subarray(0, 12);
  const tag = buf.subarray(12, 28);
  const ciphertext = buf.subarray(28);
  const decipher = createDecipheriv(ALG, KEY, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8');
}
```

Critical: the **key is not in the application database**. It lives in a separate vault (Supabase Vault, AWS KMS, HashiCorp Vault). A leaked DB backup yields ciphertext + IV + tag — useless without the key.

## Password hashing

```ts
import { hash, verify } from '@node-rs/argon2';

const ARGON2_OPTS = {
  // Tune to ~250-500ms on your production hardware
  memoryCost: 65536,        // 64 MB
  timeCost: 3,
  parallelism: 4,
};

export const hashPassword = (pw: string) => hash(pw, ARGON2_OPTS);
export const verifyPassword = (hashStr: string, pw: string) => verify(hashStr, pw);
```

Argon2id is the current OWASP recommendation. bcrypt is acceptable. **Do not** roll your own.

## Key rotation

- JWT signing keys: rotate quarterly (or annually for tokens with very short lifetime).
- Field-encryption keys: more complex — re-encrypt rows lazily (read with old key, write with new) and bump a `key_version` column.
- Signal a coming rotation in advance; never break-and-rotate the same day.

## What NOT to do

- ❌ **Don't** invent crypto primitives. Even crypto researchers don't roll their own.
- ❌ **Don't** use random number generators meant for non-crypto uses (`Math.random()` in Node, `random.random()` in Python). Use `crypto.randomBytes` / `secrets`.
- ❌ **Don't** print stack traces in production. They occasionally include in-memory secrets.
- ❌ **Don't** rely on TLS as your *only* layer of confidentiality. Encrypt at rest, too.

## References

- [OWASP A02:2021](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/)
- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
