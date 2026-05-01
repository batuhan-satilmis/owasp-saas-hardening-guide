# A08 Software & Data Integrity Failures

> Trusting input you shouldn't. Includes deserialization, unsigned updates, and webhook handlers that don't verify their caller.

## Webhook signature verification — the canonical example

```ts
// vulnerable.ts
app.post('/webhooks/stripe', async (req, res) => {
  const event = req.body;            // 🚨 trusts whoever POSTs
  if (event.type === 'invoice.paid') {
    await markSubscriptionActive(event.data.object.subscription);
  }
  res.sendStatus(200);
});
```

An attacker who knows your URL can credit themselves a paid subscription by posting a fake event.

### The fix

```ts
// secure.ts
import Stripe from 'stripe';
const stripe = new Stripe(process.env.STRIPE_SECRET!);

app.post(
  '/webhooks/stripe',
  express.raw({ type: 'application/json' }),    // raw body required for verification
  async (req, res) => {
    let event;
    try {
      event = stripe.webhooks.constructEvent(
        req.body,
        req.headers['stripe-signature']!,
        process.env.STRIPE_WEBHOOK_SECRET!
      );
    } catch {
      return res.sendStatus(401);
    }

    // Idempotency: have we processed this event before?
    const seen = await db.query(`SELECT 1 FROM stripe_events WHERE id = $1`, [event.id]);
    if (seen) return res.sendStatus(200);

    await db.transaction(async (tx) => {
      await tx.query(`INSERT INTO stripe_events (id, type) VALUES ($1, $2)`, [event.id, event.type]);
      await processEvent(tx, event);    // does the actual work
    });

    res.sendStatus(200);
  }
);
```

Two layers:

1. **Signature verification** rejects forged events.
2. **Idempotency ledger** rejects replays of legitimate events.

Both are required. The signature without the ledger lets a real Stripe event be replayed by any network attacker who saw it once.

## Idempotency keys for client-initiated mutations

If a button creates a subscription and the user clicks it twice (or the network retries), you want one subscription, not two. The pattern:

```ts
// Client supplies a UUID per logical action.
app.post('/api/subscribe', async (req, res) => {
  const idemKey = req.headers['idempotency-key'];
  if (!idemKey) return res.status(400).json({ error: 'idempotency_key_required' });

  const cached = await db.query(
    `SELECT response FROM idempotent_requests WHERE key = $1 AND user_id = $2`,
    [idemKey, req.session.userId]
  );
  if (cached) return res.json(cached.response);

  const result = await db.transaction(async (tx) => {
    const sub = await stripe.subscriptions.create({ ... }, { idempotencyKey: idemKey });
    await tx.query(
      `INSERT INTO idempotent_requests (key, user_id, response) VALUES ($1, $2, $3)`,
      [idemKey, req.session.userId, sub]
    );
    return sub;
  });

  res.json(result);
});
```

The Stripe SDK supports its own idempotency key. Use both — they protect different parts of the chain.

## Deserialization

Don't deserialize untrusted data into objects. If you must (e.g., session restoration), use a strict allow-list of types and never `eval`-style decoders.

```ts
// 🚨 vulnerable
const data = JSON.parse(userInput, (key, value) => {
  if (value && value.__type === 'Date') return new Date(value.value);
  return value;
});

// Better: validate after parse with Zod, never resurrect classes.
const data = SomeSchema.parse(JSON.parse(userInput));
```

## Build-pipeline integrity

- Lock CI runners to specific actions versions (`uses: actions/checkout@v4` is fine; pinning by SHA is better).
- Use [GitHub OIDC](https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect) for cloud deploys instead of long-lived secrets.
- Sign your release artifacts (Sigstore / cosign).

## What NOT to do

- ❌ **Don't** disable signature verification "for testing." Make a separate test path.
- ❌ **Don't** auto-update production from a "latest" container tag. Pin by digest.
- ❌ **Don't** parse JWTs without verifying their signature. (The number of "decoded with `jwt.decode`" CVEs is sad.)

## References

- [OWASP A08:2021](https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/)
- [Stripe webhook signing docs](https://stripe.com/docs/webhooks/signatures)
