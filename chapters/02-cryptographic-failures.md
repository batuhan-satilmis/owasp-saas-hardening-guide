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

## Worked example: timing-safe comparison of secrets

You verify a partner's webhook, or a password-reset token, or an API key. You compute the expected value, then compare it to what the caller sent. If you reach for `===`, you have accidentally built a network-facing timing oracle. This is the crypto bug most likely to survive code review at a SaaS I've audited — the vulnerable version *works* in every functional test and looks obviously correct.

### The vulnerable handler

```ts
// vulnerable.ts — HMAC verification for a partner webhook
import { Request, Response } from 'express';
import { createHmac } from 'node:crypto';

const PARTNER_SECRET = process.env.PARTNER_WEBHOOK_SECRET!;

export function verifyPartnerWebhook(req: Request, res: Response, next: () => void) {
  const providedSig = req.header('X-Partner-Signature') ?? '';
  const expectedSig = createHmac('sha256', PARTNER_SECRET)
    .update(req.rawBody)               // raw buffer captured by express.raw()
    .digest('hex');

  if (expectedSig !== providedSig) {   // 🚨 timing-leak: string comparison short-circuits
    return res.sendStatus(401);
  }
  next();
}
```

And its cousin, on the password-reset path:

```ts
// vulnerable.ts — password-reset token check
export async function completeReset(req: Request, res: Response) {
  const { userId, token, newPassword } = req.body;
  const row = await db.query(
    `SELECT reset_token, expires_at FROM password_resets WHERE user_id = $1`,
    [userId],
  );
  if (!row || row.expires_at < new Date()) return res.sendStatus(400);

  if (row.reset_token !== token) {     // 🚨 same class of leak
    return res.sendStatus(400);
  }
  await setPassword(userId, newPassword);
  await db.query(`DELETE FROM password_resets WHERE user_id = $1`, [userId]);
  res.sendStatus(204);
}
```

Both handlers behave correctly for legitimate traffic. Every unit test passes. Postman calls succeed. There is nothing an obvious code reviewer catches — the bug is invisible until you measure response latency at nanosecond resolution.

### Why it's exploitable

V8 (and every other JavaScript engine) compares strings byte-by-byte and returns on the first mismatch. Same for `Buffer.equals` when used on unequal-length inputs. That means the response time for `expectedSig !== providedSig` grows very slightly the more leading bytes the attacker guesses correctly. The signal per request is small — typically 10–50 nanoseconds per byte on a warm cache — but it aggregates cleanly under statistical averaging over thousands of requests.

Three practical points people get wrong:

- **"Cloud latency drowns it out"** — no. Network jitter is roughly Gaussian; the timing signal is a fixed offset. With enough samples the mean separates from the noise floor. Nate Lawson's 2009 Blackhat talk demonstrated this working across the public internet.
- **"HTTPS hides the response body from timing analysis"** — irrelevant. The attacker is measuring wall-clock RTT of a `401` response, not decrypting anything.
- **"A hex-encoded HMAC has 64 characters; that's too much search space"** — the attack is byte-by-byte, so cost scales linearly (~5–30 minutes at 5k req/s to recover a 32-byte HMAC in a controlled setting), not exponentially.

The same class of leak exists for password-reset tokens, unsubscribe tokens, API keys, MFA backup codes, and any bearer credential your service *generates itself* and later compares.

### The fix

```ts
// safe/compareSecrets.ts — the canonical helper. Import this everywhere.
import { timingSafeEqual } from 'node:crypto';

/**
 * Constant-time comparison of two byte sequences. Returns false for any
 * length mismatch or malformed input without ever throwing.
 *
 * Never compare secrets, HMAC digests, or tokens with === or Buffer.equals
 * on user-controlled input. Use this instead.
 */
export function secretsEqual(a: Buffer | string, b: Buffer | string): boolean {
  const bufA = Buffer.isBuffer(a) ? a : Buffer.from(a, 'utf8');
  const bufB = Buffer.isBuffer(b) ? b : Buffer.from(b, 'utf8');
  // timingSafeEqual throws RangeError on mismatched length — a length check
  // is not itself a timing leak because the attacker already knows the
  // expected length (it's fixed by our protocol).
  if (bufA.length !== bufB.length) return false;
  return timingSafeEqual(bufA, bufB);
}
```

Now the fixed handlers:

```ts
// secure.ts — HMAC verification
import { createHmac } from 'node:crypto';
import { secretsEqual } from './safe/compareSecrets';

export function verifyPartnerWebhook(req: Request, res: Response, next: () => void) {
  const providedHex = req.header('X-Partner-Signature') ?? '';
  // Reject malformed hex early — Buffer.from(_, 'hex') silently truncates on
  // odd characters, which would make a wrong-length signature look valid-length.
  if (!/^[0-9a-f]{64}$/.test(providedHex)) return res.sendStatus(401);

  const expected = createHmac('sha256', PARTNER_SECRET)
    .update(req.rawBody)
    .digest();                         // Buffer, not hex
  const provided = Buffer.from(providedHex, 'hex');

  if (!secretsEqual(expected, provided)) return res.sendStatus(401);
  next();
}
```

```ts
// secure.ts — password-reset token check
export async function completeReset(req: Request, res: Response) {
  const { userId, token, newPassword } = req.body;
  const row = await db.query(
    `SELECT reset_token, expires_at, used_at FROM password_resets WHERE user_id = $1`,
    [userId],
  );
  if (!row || row.used_at || row.expires_at < new Date()) return res.sendStatus(400);

  if (!secretsEqual(row.reset_token, token)) return res.sendStatus(400);

  // Mark used *before* setting the password so a lost race can't burn the token twice.
  await db.transaction(async (tx) => {
    const marked = await tx.query(
      `UPDATE password_resets SET used_at = now()
         WHERE user_id = $1 AND used_at IS NULL
       RETURNING 1`,
      [userId],
    );
    if (marked.length !== 1) throw new Error('token race');
    await setPassword(tx, userId, newPassword);
  });
  res.sendStatus(204);
}
```

Two independent fixes are folded into the reset handler: constant-time comparison *and* a one-shot `used_at` guard. The token comparison stops the timing attack; the `used_at` guard stops the well-known reset-token replay problem (see A07 chapter). Both are cheap; both belong.

### Tests (Vitest)

```ts
// tests/secretsEqual.test.ts
import { describe, it, expect } from 'vitest';
import { randomBytes } from 'node:crypto';
import { secretsEqual } from '../src/safe/compareSecrets';

describe('secretsEqual', () => {
  it('returns true for byte-identical Buffers', () => {
    const a = randomBytes(32);
    expect(secretsEqual(a, Buffer.from(a))).toBe(true);
  });

  it('returns true for byte-identical strings', () => {
    expect(secretsEqual('correct-horse-battery-staple', 'correct-horse-battery-staple')).toBe(true);
  });

  it('returns false for same-length but different Buffers', () => {
    const a = randomBytes(32);
    const b = Buffer.from(a);
    b[17] ^= 0x01;                     // flip one bit
    expect(secretsEqual(a, b)).toBe(false);
  });

  it('returns false — not throws — on length mismatch', () => {
    expect(() => secretsEqual(randomBytes(32), randomBytes(31))).not.toThrow();
    expect(secretsEqual(randomBytes(32), randomBytes(31))).toBe(false);
  });

  it('returns false — not throws — for empty inputs vs. non-empty', () => {
    expect(secretsEqual('', 'anything')).toBe(false);
    expect(secretsEqual('anything', '')).toBe(false);
  });

  it('accepts mixed Buffer/string inputs consistently', () => {
    const s = 'abc123';
    expect(secretsEqual(Buffer.from(s, 'utf8'), s)).toBe(true);
    expect(secretsEqual(s, Buffer.from(s, 'utf8'))).toBe(true);
  });
});
```

```ts
// tests/verifyPartnerWebhook.test.ts
import { describe, it, expect } from 'vitest';
import { createHmac } from 'node:crypto';
import request from 'supertest';
import { app } from '../src/app';

const SECRET = process.env.PARTNER_WEBHOOK_SECRET!;
const sign = (body: string) => createHmac('sha256', SECRET).update(body).digest('hex');

describe('POST /webhooks/partner', () => {
  it('accepts a correctly signed body', async () => {
    const body = JSON.stringify({ event: 'ping' });
    await request(app).post('/webhooks/partner')
      .set('X-Partner-Signature', sign(body))
      .set('Content-Type', 'application/json')
      .send(body)
      .expect(200);
  });

  it('rejects a body with a one-byte-off signature', async () => {
    const body = JSON.stringify({ event: 'ping' });
    const bad = sign(body).slice(0, -2) + '00';
    await request(app).post('/webhooks/partner')
      .set('X-Partner-Signature', bad)
      .set('Content-Type', 'application/json')
      .send(body)
      .expect(401);
  });

  it('rejects malformed hex (odd length, non-hex chars) with 401 — not 500', async () => {
    for (const junk of ['not-hex', 'aabbc', 'z'.repeat(64), '']) {
      await request(app).post('/webhooks/partner')
        .set('X-Partner-Signature', junk)
        .set('Content-Type', 'application/json')
        .send('{}')
        .expect(401);
    }
  });

  it('rejects the vulnerable pattern: signature computed against a different body', async () => {
    await request(app).post('/webhooks/partner')
      .set('X-Partner-Signature', sign('{"event":"other"}'))
      .set('Content-Type', 'application/json')
      .send('{"event":"ping"}')
      .expect(401);
  });
});
```

I don't ship a timing-attack regression test in CI — it's inherently flaky under shared-runner jitter and the effect size is below the noise floor of a single-run benchmark. The right defense is the primitive itself (`timingSafeEqual`), enforced by lint. A rule like `eslint-plugin-security`'s `detect-possible-timing-attacks` catches naive `===` on names that match `/secret|token|password|hash|hmac|sig/i` at review time; that's the cheap belt-and-braces layer.

### Where you must use this

Anywhere you *generate* a secret and later compare it against user-supplied input:

- Custom HMAC / webhook signature verification (Stripe's SDK already does this — [A08 chapter](./08-software-data-integrity.md#webhook-signature-verification--the-canonical-example) — but partner integrations you write yourself do not).
- Password-reset, email-verification, and MFA-recovery tokens.
- API keys and internal service-to-service bearer tokens.
- Unsubscribe / one-click-action tokens in transactional emails.
- Session-fixation defense tokens (double-submit CSRF cookie vs. header).

You do *not* need constant-time comparison for values the attacker already knows (public identifiers, request IDs, error codes). The rule is: if guessing the value gives the attacker something they didn't have before, compare it in constant time.

### Review rubric

- [ ] No `===`, `!==`, `Buffer.equals`, or `String.prototype.localeCompare` on any variable whose name contains `token`, `secret`, `password`, `hash`, `hmac`, `sig`, or `key`.
- [ ] Length of user-supplied secret validated *before* decoding into a Buffer (regex on the wire format).
- [ ] Comparison goes through the single `secretsEqual` helper — one import site, one code path, one place to audit.
- [ ] For tokens with lifecycle (reset, verification, MFA-recovery): comparison is paired with a one-shot `used_at`/`consumed_at` guard inside the same transaction.

### Related material

- [A08 §Webhook signature verification](./08-software-data-integrity.md#webhook-signature-verification--the-canonical-example) — Stripe SDK path where the timing-safe comparison happens for you.
- [A07 §Password reset](./07-identification-authentication.md) — the lifecycle rules for reset tokens (expiry, one-shot, rate limit) that pair with the constant-time comparison here.
- [api-security-checklist / webhooks](https://github.com/batuhan-satilmis/api-security-checklist/blob/main/chapters/webhooks.md) — companion checklist for partner webhook design.
- [api-security-checklist / logging](https://github.com/batuhan-satilmis/api-security-checklist/blob/main/chapters/logging.md) — signature failures are a high-signal alerting channel; log them.

## What NOT to do

- ❌ **Don't** invent crypto primitives. Even crypto researchers don't roll their own.
- ❌ **Don't** use random number generators meant for non-crypto uses (`Math.random()` in Node, `random.random()` in Python). Use `crypto.randomBytes` / `secrets`.
- ❌ **Don't** print stack traces in production. They occasionally include in-memory secrets.
- ❌ **Don't** rely on TLS as your *only* layer of confidentiality. Encrypt at rest, too.

## References

- [OWASP A02:2021](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/)
- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
