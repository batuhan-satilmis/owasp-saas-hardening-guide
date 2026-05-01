# A01 Broken Access Control

> The #1 risk on the OWASP Top 10 (2021), and the source of more SaaS data leaks than every other category combined. The fix is conceptually simple — *enforce access at every layer that can be reached* — and operationally tricky.

## The bug

A naive Express handler that fetches a customer record by ID:

```ts
// vulnerable.ts
app.get('/api/customers/:id', requireAuth, async (req, res) => {
  const customer = await db.query(
    'SELECT * FROM customers WHERE id = $1',
    [req.params.id]
  );
  if (!customer) return res.status(404).end();
  res.json(customer);
});
```

What's wrong:

1. **Insecure Direct Object Reference (IDOR)**: any authenticated user can request any customer ID and get the data, regardless of which tenant they belong to.
2. **No tenant scoping**: a user in Tenant A can read Tenant B's customer.
3. **No role check**: a `viewer` can read what only `tenant_admin` should see.

Real-world cost: this is the bug class that produced the [Optus breach](https://en.wikipedia.org/wiki/2022_Optus_data_breach) (10M records), the [USPS Informed Visibility leak](https://krebsonsecurity.com/2018/11/usps-site-exposed-data-on-60-million-users/) (60M), and most of the IDOR-class CVEs filed against B2B SaaS vendors every year.

## The fix

Three layers. Defense-in-depth is *especially* important here because a single missed `WHERE` is enough to leak everything.

### Layer 1 — API: scope the query by the requester's tenant

```ts
// secure.ts (layer 1)
app.get('/api/customers/:id', requireAuth, async (req, res) => {
  const tenantId = req.session.tenantId;       // server-side, never from client
  const customer = await db.query(
    'SELECT * FROM customers WHERE id = $1 AND tenant_id = $2',
    [req.params.id, tenantId]
  );
  if (!customer) return res.status(404).end();
  res.json(customer);
});
```

Note `tenantId` comes from the *server-issued session*, not the request body or path. Never accept tenant identity from the client.

### Layer 2 — API middleware: declare required role explicitly

```ts
// secure.ts (layer 2)
const requireRole = (allowed: Role[]) => (req, res, next) => {
  if (!allowed.includes(req.session.role)) return res.status(403).end();
  next();
};

app.get(
  '/api/customers/:id',
  requireAuth,
  requireRole(['tenant_admin', 'tenant_owner', 'member']),
  customerHandler
);
```

The role list is per-route. **Don't** centralize "is this user allowed to do anything" — centralize "what does this specific endpoint require." It reads better in code review and catches more bugs.

### Layer 3 — Database: Postgres Row-Level Security

This is the layer most teams skip and most often regret.

```sql
ALTER TABLE customers ENABLE ROW LEVEL SECURITY;
ALTER TABLE customers FORCE  ROW LEVEL SECURITY;  -- applies to table owner too

CREATE POLICY tenant_isolation ON customers
  USING (tenant_id = current_setting('jwt.claim.tenant_id')::uuid);
```

Now: even if Layer 1 forgets the `AND tenant_id = ...`, the database refuses to return another tenant's rows. RLS is your last line of defense. Use `FORCE` so even superuser connections respect it.

> **Pattern**: every request gets a Postgres connection where the JWT has been parsed and `jwt.claim.tenant_id` is set on the session. Supabase does this for you; with raw `pg` you do it via `SET LOCAL`.

## What NOT to do

- ❌ **Don't** read `tenant_id` from the request body, path, or query string for authorization purposes.
- ❌ **Don't** rely solely on the API for tenant isolation. *Every* successful B2B data-leak post-mortem has the words "we forgot to add `WHERE tenant_id =` in this one query."
- ❌ **Don't** use UUIDs as a security boundary. UUIDs are a usability feature; RLS is the security boundary.
- ❌ **Don't** check authorization in the frontend. The frontend is the attacker's environment.
- ❌ **Don't** "improve" by opening a wide read scope and filtering in application code. The DB is the right place for the filter.

## The test that catches the bad version

```ts
// 01-broken-access-control.test.ts
import { request } from './testHelpers';

test('User in Tenant A cannot read Tenant B customers', async () => {
  const tenantA = await seedTenant('A', { customers: 3 });
  const tenantB = await seedTenant('B', { customers: 1 });

  const userA = await loginAs(tenantA.users[0]);

  // Try to read every customer in B by guessing IDs:
  for (const customer of tenantB.customers) {
    const res = await request().get(`/api/customers/${customer.id}`)
      .set('Cookie', userA.cookie);
    expect(res.status).toBe(404);   // not 403, to avoid existence oracle
  }
});

test('Viewer cannot reach admin-only endpoint', async () => {
  const tenant = await seedTenant('A', { roles: ['viewer'] });
  const viewer = await loginAs(tenant.users[0]);

  const res = await request().delete(`/api/customers/${tenant.customers[0].id}`)
    .set('Cookie', viewer.cookie);
  expect(res.status).toBe(403);
});
```

Run this on every CI build. If it passes when one of the layers is removed, your test isn't testing what it claims.

## Pitfalls I've seen in production reviews

| Pitfall | Why it bites |
|---|---|
| 404 vs 403 leakage | Returning 403 for "exists but not allowed" lets attackers enumerate IDs. Always return 404 for "you can't see it," reserve 403 for "you're authenticated but lack the role on a resource you legitimately know exists." |
| RLS policies against `auth.uid()` only, no tenant | Catches user-level isolation, misses tenant-level. Common Supabase mistake. |
| Frontend hides the button so "users can't" | The handler is still callable directly. Always test the API, not the UI. |
| `SELECT * FROM ... ORDER BY created_at` style listings | Pagination + filter on tenant_id is mandatory. `ORDER BY` does not constrain the result set. |
| Admin endpoints behind `/api/admin/` only | An attacker with API knowledge will still call them. Path is documentation, not security. |

## Related chapters

- [A04 Insecure Design](./04-insecure-design.md) — preventing this class of bug at design time, not just at code time.
- [A07 Identification & Authentication Failures](./07-identification-authentication.md) — the access-control system relies on knowing who's calling.
- [A09 Logging & Monitoring Failures](./09-logging-monitoring.md) — log attempted cross-tenant access; it's one of the highest-signal alerts you can produce.

## References

- [OWASP A01:2021 — Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
- [Supabase RLS guide](https://supabase.com/docs/guides/auth/row-level-security)
- [PostgreSQL RLS docs](https://www.postgresql.org/docs/current/ddl-rowsecurity.html)
