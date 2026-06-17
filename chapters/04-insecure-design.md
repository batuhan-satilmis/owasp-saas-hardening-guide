# A04 Insecure Design

> Most categories on the OWASP Top 10 are about *implementation*. This one is about *design* — security controls that should have been thought of before the code was written. The fix is process, not patch.

## What it looks like

- The product allows password reset by knowing only the user's email and last 4 of their phone — so an attacker who finds those on social media owns the account.
- "Forgot username" sends the username in an email — fine, except the same form is also the user-enumeration oracle.
- The export endpoint produces a CSV containing every column, including soft-deleted rows and PII you intended to redact.
- Discount codes are validated client-side. The cart total is whatever the client sends.

These aren't bugs you can lint for. They're missing requirements.

## How to design this in

### Threat-model every major feature

Before code, write a STRIDE worksheet. Even a 30-minute pass catches most missing requirements. Use the [companion threat-modeling-framework](https://github.com/batuhan-satilmis/threat-modeling-framework) repo — it has the templates.

### Document trust boundaries

Draw the boundaries explicitly. For each one, write down "what crosses, and why is the receiver willing to trust it?" This is how you notice that a frontend "trusted" zone is actually attacker territory.

### Make the *secure* path the *easy* path

If your codebase has a `db.raw(...)` and a parameterized `db.query(...)`, lint to ban the first. If the auth-aware route base requires a role declaration, no one can ship a route that forgot one. Frame ergonomics around the security goal.

### Have a "what could go wrong" review checklist

Before merging a PR that adds a new endpoint, ask:

- [ ] Does this endpoint require authentication?
- [ ] If yes, what role(s)?
- [ ] Is access scoped to the caller's tenant?
- [ ] Are inputs validated with a schema?
- [ ] Is the rate limit appropriate?
- [ ] Are errors sanitized in production?
- [ ] Is anything in the response a privacy leak (other-user data, internal IDs, version numbers)?
- [ ] Does it write to the audit log if it's a privileged action?

This list lives in `.github/PULL_REQUEST_TEMPLATE.md` and is checked by reviewer.

---

## Worked example: server-trusted pricing at checkout

The bullet above ("Discount codes are validated client-side. The cart total is whatever the client sends.") deserves a concrete walkthrough — it's the design-level bug I see most often in startup SaaS pre-launch reviews, and it's almost always introduced because the frontend already had the numbers, so re-sending them felt natural.

### Vulnerable handler

```ts
// POST /api/checkout — the client posts what it wants to pay
app.post('/api/checkout', requireAuth, async (req, res) => {
  const { items, discountCode, total } = req.body;

  // Naive "apply discount": trust the client's `total` if the code looks valid
  let finalTotal = total;
  if (discountCode) {
    const code = await db.coupon.findUnique({ where: { code: discountCode } });
    if (code?.active) finalTotal = total * (1 - code.percentOff / 100);
  }

  await stripe.paymentIntents.create({
    amount: Math.round(finalTotal * 100),
    currency: 'usd',
    metadata: { userId: req.user.id, items: JSON.stringify(items) },
  });
  res.json({ ok: true });
});
```

Three independent failures, any one of which is enough:

1. **`total` is attacker-controlled.** Curl with `{ items: [...], total: 0.01 }` ships the order for one cent.
2. **`items` is attacker-controlled.** Even if the client recomputes correctly, the server never re-prices, so swapping a $5 SKU for a $500 one in the cart is free.
3. **Discount stacking / reuse.** No check that the code is per-user, single-use, or applicable to these items.

This is an A04 finding rather than A03 or A01: the inputs *are* validated (schema-checked, authenticated) — the design simply puts the price authority on the wrong side of the trust boundary.

### Fix: the server is the price authority

```ts
// POST /api/checkout — the client only references catalog IDs
app.post('/api/checkout', requireAuth, async (req, res) => {
  const { itemIds, discountCode } = checkoutSchema.parse(req.body);

  // 1. Look up authoritative prices from the catalog. Never trust the cart.
  const items = await db.product.findMany({
    where: { id: { in: itemIds }, active: true },
    select: { id: true, priceCents: true },
  });
  if (items.length !== itemIds.length) {
    return res.status(400).json({ error: 'unknown_or_inactive_item' });
  }
  const subtotalCents = items.reduce((sum, p) => sum + p.priceCents, 0);

  // 2. Apply discount under a transactional lock that prevents reuse.
  const finalCents = await db.$transaction(async (tx) => {
    let cents = subtotalCents;
    if (discountCode) {
      const code = await tx.coupon.findUnique({
        where: { code: discountCode },
        select: { id: true, percentOff: true, perUserLimit: true, expiresAt: true },
      });
      if (!code || (code.expiresAt && code.expiresAt < new Date())) {
        throw new HttpError(400, 'invalid_coupon');
      }
      const uses = await tx.couponRedemption.count({
        where: { couponId: code.id, userId: req.user.id },
      });
      if (uses >= code.perUserLimit) throw new HttpError(400, 'coupon_already_used');

      await tx.couponRedemption.create({
        data: { couponId: code.id, userId: req.user.id },
      });
      cents = Math.round(cents * (1 - code.percentOff / 100));
    }
    return cents;
  });

  const intent = await stripe.paymentIntents.create({
    amount: finalCents,
    currency: 'usd',
    metadata: { userId: req.user.id, itemIds: itemIds.join(',') },
  });
  res.json({ clientSecret: intent.client_secret });
});
```

What changed:

- **The request body no longer contains a price**, only catalog IDs. The server re-prices on every checkout, full stop.
- **Money is integer cents end-to-end.** Floating-point math (`total * (1 - percentOff/100)`) is a separate bug class — see the cryptography chapter's "don't roll your own" theme for why approximate arithmetic on money goes wrong.
- **Coupon redemption is recorded inside the same transaction** that computes the discount. The `couponRedemption (couponId, userId)` unique constraint prevents two concurrent requests from both reading `uses = 0` and both applying the discount. See [threat-modeling-framework T-016](https://github.com/batuhan-satilmis/threat-modeling-framework) for the worked race-condition threat.
- **The Stripe `amount` is whatever the server just computed**, never echoed from the client. The webhook handler later verifies the captured amount equals what we stored against the order — see the webhook chapter in `api-security-checklist` for that half.

### Test that catches the bad version

```ts
// tests/checkout.test.ts
import { describe, expect, it } from 'vitest';
import request from 'supertest';
import { app } from '../src/app';
import { signSessionCookie, seedProduct, seedCoupon } from './helpers';

describe('POST /api/checkout — pricing trust boundary', () => {
  const cookie = signSessionCookie({ userId: 'u1' });

  it('rejects a request that includes a client-supplied total', async () => {
    await seedProduct({ id: 'p1', priceCents: 50_00, active: true });
    const res = await request(app)
      .post('/api/checkout')
      .set('Cookie', cookie)
      .send({ itemIds: ['p1'], total: 0.01 });
    // Schema rejects unknown `total` field — zod strict() / .strip() depending on policy
    expect(res.status).toBe(400);
  });

  it('charges the catalog price, not whatever the client implies', async () => {
    await seedProduct({ id: 'p2', priceCents: 500_00, active: true });
    const res = await request(app)
      .post('/api/checkout')
      .set('Cookie', cookie)
      .send({ itemIds: ['p2'] });
    expect(res.status).toBe(200);
    // Test double for Stripe captures the call args
    expect(stripeStub.lastCall.amount).toBe(500_00);
  });

  it('refuses unknown or inactive items', async () => {
    await seedProduct({ id: 'p3', priceCents: 10_00, active: false });
    const res = await request(app)
      .post('/api/checkout')
      .set('Cookie', cookie)
      .send({ itemIds: ['p3'] });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('unknown_or_inactive_item');
  });

  it('prevents the same coupon being redeemed twice by one user, even under a race', async () => {
    await seedProduct({ id: 'p4', priceCents: 100_00, active: true });
    await seedCoupon({ code: 'WELCOME50', percentOff: 50, perUserLimit: 1 });
    const fire = () =>
      request(app)
        .post('/api/checkout')
        .set('Cookie', cookie)
        .send({ itemIds: ['p4'], discountCode: 'WELCOME50' });

    const [a, b] = await Promise.all([fire(), fire()]);
    const statuses = [a.status, b.status].sort();
    expect(statuses).toEqual([200, 400]);
    const ok = a.status === 200 ? a : b;
    const fail = a.status === 400 ? a : b;
    expect(stripeStub.calls.find((c) => c.id === ok.body.clientSecret)?.amount).toBe(50_00);
    expect(fail.body.error).toBe('coupon_already_used');
  });
});
```

Four tests, one per failure mode in the vulnerable version. The race-condition test is the one most reviews skip — if you only test sequential calls, the unique-constraint approach and a `Math.random() < 0.5` check both pass. Concurrency is part of the design, not an afterthought.

### How to spot this in review

When reading any checkout, billing, points-redemption, or quota-consumption handler, the questions are always:

- Where does each number in the response come from? If any of them came from the request body, the request body is the price authority — that's the bug.
- Is the deduction (of coupon, credit, quota) inside the same transaction as the read of how much remains? If not, two concurrent requests can both "succeed."
- Does the database have a uniqueness constraint that *enforces* the business rule, or are we relying on application-layer "check then act"? Always the former.

## What NOT to do

- ❌ **Don't** treat security review as a one-time pre-launch event. Things change.
- ❌ **Don't** rely on "we'll add it later." It's harder later.
- ❌ **Don't** assume happy-path. The attacker is testing every edge of every input you didn't think to test.

## References

- [OWASP A04:2021](https://owasp.org/Top10/A04_2021-Insecure_Design/)
- [Threat modeling repo](https://github.com/batuhan-satilmis/threat-modeling-framework)
