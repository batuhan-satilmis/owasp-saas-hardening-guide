# A07 Identification & Authentication Failures

> Auth bugs are where the worst breaches come from. This chapter focuses on the four that bite SaaS hardest: weak session handling, refresh-token theft, credential-stuffing, and password reset.

## Session handling: cookies, not local storage

```ts
// vulnerable.ts — token in the response body, browser stores in localStorage
app.post('/api/login', async (req, res) => {
  const user = await authenticate(req.body.email, req.body.password);
  if (!user) return res.status(401).end();
  const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET, { expiresIn: '7d' });
  res.json({ token });   // 🚨 frontend stores in localStorage; XSS = full account takeover
});
```

Two problems:

1. **localStorage is reachable from any JavaScript on the page.** A single XSS in your own code or a third-party dependency exfiltrates the token.
2. **7-day JWTs.** Long-lived tokens cannot be revoked centrally without an extra ledger, and the value to an attacker is correspondingly high.

### Fix

```ts
// secure.ts
app.post('/api/login', loginRateLimit, async (req, res) => {
  const { email, password } = LoginInput.parse(req.body);
  const user = await authenticate(email, password);
  if (!user) {
    await sleepRandom(50, 150);    // constant-time-ish, defeat user-enumeration timing
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  const sessionId = await createSession(user.id, {
    ip: req.ip,
    userAgent: req.headers['user-agent'],
  });

  res.cookie('session', sessionId, {
    httpOnly: true,         // JS cannot read it
    secure: true,           // HTTPS only
    sameSite: 'strict',     // CSRF defense in depth
    maxAge: 7 * 24 * 3600 * 1000,
    path: '/',
  });
  res.json({ user: publicUser(user) });
});
```

- Session ID is opaque and stored server-side. Logout means *deleting the row*, not telling the client to forget.
- HttpOnly cookies are unreachable to JavaScript. XSS no longer == game over.
- SameSite=Strict adds CSRF defense in depth.
- `secure: true` means the cookie cannot be sent over HTTP. Pair with HSTS preload at the edge.

## Refresh-token rotation with reuse detection

The pattern that turns refresh-token theft into a self-detecting incident:

```ts
// secure.ts (refresh handler)
app.post('/api/refresh', async (req, res) => {
  const presented = req.cookies.refresh;
  if (!presented) return res.status(401).end();

  const tokenRow = await db.query(
    `SELECT id, user_id, family_id, used FROM refresh_tokens WHERE token_hash = $1`,
    [sha256(presented)]
  );

  if (!tokenRow) {
    return res.status(401).end();
  }

  if (tokenRow.used) {
    // 🚨 someone presented a token we already rotated.
    // Either a network replay, or a stolen token being used by a thief.
    // We can't tell which. Be paranoid: kill the family.
    await db.query(`UPDATE refresh_tokens SET revoked = true WHERE family_id = $1`, [tokenRow.family_id]);
    await db.query(`UPDATE sessions SET revoked = true WHERE refresh_family_id = $1`, [tokenRow.family_id]);
    auditLog('auth.refresh_reuse_detected', { userId: tokenRow.user_id });
    return res.status(401).end();
  }

  // Mark old as used; issue a new one in the same family.
  await db.transaction(async (tx) => {
    await tx.query(`UPDATE refresh_tokens SET used = true WHERE id = $1`, [tokenRow.id]);
    const newToken = randomBase64(32);
    await tx.query(
      `INSERT INTO refresh_tokens (token_hash, family_id, user_id) VALUES ($1, $2, $3)`,
      [sha256(newToken), tokenRow.family_id, tokenRow.user_id]
    );
    res.cookie('refresh', newToken, refreshCookieOpts);
  });
});
```

Key points:

- **One-time use.** Refresh tokens are rotated on every refresh. The DB enforces this with a `used` flag.
- **Family**. All refresh tokens descended from a single login share a `family_id`. If any token in the family is presented twice, kill the whole family — every session derived from that login dies.
- **Stored hashed.** The cleartext token never touches durable storage; only `sha256(token)` does.

This is the [OWASP-recommended pattern](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html#token-storage-on-server-side). It does not prevent token theft; it makes theft loud.

## Login rate-limiting without the lockout footgun

```ts
import rateLimit from 'express-rate-limit';

export const loginRateLimit = rateLimit({
  windowMs: 60_000,
  max: 5,                         // per IP
  message: { error: 'Too many requests' },
  standardHeaders: true,
});
```

You also want a *user-side* limit — but **don't lock the account**. That lets an attacker DoS any user just by typing wrong passwords. Instead:

- Slow the attacker (`sleep` for ~1s on each failed attempt past N).
- Require a CAPTCHA after N failures.
- Alert on the user.
- Never expose the existence of the account through the lockout response.

## Password reset that doesn't leak emails

```ts
// secure.ts
app.post('/api/password-reset/request', resetRateLimit, async (req, res) => {
  const { email } = z.object({ email: z.string().email() }).parse(req.body);
  const user = await db.users.findByEmail(email);
  if (user) {
    const token = randomBase64(32);
    await db.passwordResets.create({
      userId: user.id,
      tokenHash: sha256(token),
      expiresAt: new Date(Date.now() + 15 * 60_000),   // 15 min
    });
    await sendResetEmail(email, token);
  }
  // Identical response, regardless of whether email exists. Defeats enumeration.
  return res.json({ ok: true, message: 'If that email exists, a reset link was sent.' });
});
```

Critical points:

- Same response for "found" and "not found." The timing should also match — see the `sleepRandom` pattern earlier.
- Token is single-use (delete after consumption).
- Token is short-lived (15 minutes is plenty).
- Token is stored hashed.

Common mistake: returning HTTP 200 vs 404 based on existence. That's enumeration in plain HTTP.

## Credential stuffing defense

Stuffing is the attacker bringing a list of (email, password) pairs leaked from someone else's breach and trying them all. You can't stop it entirely without breaking UX, but you *can*:

| Layer | Control |
|---|---|
| Edge | Block known-bad IPs (Cloudflare, etc.). Block traffic from high-risk ASNs / Tor exits if your audience doesn't need them. |
| App | Rate limit per IP and per email. Slow each subsequent failure. |
| App | Add a CAPTCHA after N failed logins from an IP — even if the email is different. |
| Database | Check submitted password against [Have I Been Pwned's password API](https://haveibeenpwned.com/Passwords) (k-anonymity model — you only send the SHA-1 prefix) on **registration** and **password change**. |
| Detection | Alert on a single IP making login attempts against many distinct emails — that's the stuffing signature. |

## What NOT to do

- ❌ **Don't** ship JWTs with `alg: none` accepted. Some old libraries do by default. Lock the algorithm explicitly.
- ❌ **Don't** put authentication state in URL parameters. They end up in logs, browser history, referrer headers.
- ❌ **Don't** re-authenticate by the email-and-token-in-link pattern as a primary login flow. Magic links are fine for low-risk; not for production B2B.
- ❌ **Don't** require users to change passwords every 90 days for compliance theater. NIST 800-63B explicitly recommends *against* this — it produces predictable patterns.
- ❌ **Don't** enforce bizarre password complexity rules ("must have a special character"). NIST 800-63B says length over composition. Cap at no shorter than 8, no upper bound below 64.

## The test that catches the bad version

```ts
test('refresh-token reuse kills the entire session family', async () => {
  const user = await seedUser();
  const { sessionCookie, refreshCookie } = await login(user);

  // First refresh — should succeed and return a new refresh cookie.
  const r1 = await request().post('/api/refresh').set('Cookie', refreshCookie);
  expect(r1.status).toBe(200);
  const newRefresh = parseSetCookie(r1.headers['set-cookie']).refresh;

  // Replay the *original* refresh token. This should be detected.
  const r2 = await request().post('/api/refresh').set('Cookie', refreshCookie);
  expect(r2.status).toBe(401);

  // The "good" new refresh should also now be rejected — entire family killed.
  const r3 = await request().post('/api/refresh').set('Cookie', `refresh=${newRefresh}`);
  expect(r3.status).toBe(401);

  // Audit log should record the reuse event.
  const events = await db.query(`SELECT * FROM audit_log WHERE event = 'auth.refresh_reuse_detected'`);
  expect(events.length).toBe(1);
});
```

## Related chapters

- [A01 Broken Access Control](./01-broken-access-control.md) — auth answers "who"; access control answers "what they can do." Both must be right.
- [A09 Logging & Monitoring Failures](./09-logging-monitoring.md) — `auth.refresh_reuse_detected` is one of the highest-signal alerts in the app.

## References

- [OWASP A07:2021](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/)
- [NIST SP 800-63B Digital Identity Guidelines](https://pages.nist.gov/800-63-3/sp800-63b.html)
- [OWASP JWT for Java Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)
- [Have I Been Pwned password API](https://haveibeenpwned.com/API/v3#PwnedPasswords)
