# A03 Injection

> SQL, command, NoSQL, LDAP — same root cause: user input concatenated into a structural query without escaping. The fix is uniform: separate code from data. Always.

## The bug

```ts
// vulnerable.ts
app.get('/api/search', requireAuth, async (req, res) => {
  const q = req.query.q;
  const sql = `SELECT id, name FROM customers
               WHERE tenant_id = '${req.session.tenantId}'
                 AND name ILIKE '%${q}%'`;
  const result = await db.query(sql);    // 🚨
  res.json(result.rows);
});
```

What's wrong: the `q` query parameter and even `tenantId` are interpolated into a SQL string. An attacker sends:

```
?q=' OR '1'='1
?q=' UNION SELECT id, password_hash FROM users--
```

…and reads everything they want. Even if `tenantId` comes from the session, the moment user input is interpolated, the whole query is hostile-controlled.

## The fix

### Use parameter binding. Always.

```ts
// secure.ts
app.get('/api/search', requireAuth, async (req, res) => {
  const q = String(req.query.q ?? '').slice(0, 100);
  const result = await db.query(
    `SELECT id, name FROM customers
     WHERE tenant_id = $1 AND name ILIKE $2`,
    [req.session.tenantId, `%${q}%`]
  );
  res.json(result.rows);
});
```

`$1`, `$2` are placeholders. The driver sends them as separate values to the database, which treats them as data, not code, regardless of contents. It is **impossible** to inject SQL through a properly bound parameter.

### Validate input at the boundary

```ts
import { z } from 'zod';

const SearchInput = z.object({
  q: z.string().min(0).max(100),
  page: z.coerce.number().int().min(1).max(1000).default(1),
});

app.get('/api/search', requireAuth, async (req, res) => {
  const input = SearchInput.parse(req.query);
  const result = await db.query(
    `SELECT id, name FROM customers
     WHERE tenant_id = $1 AND name ILIKE $2
     LIMIT 50 OFFSET $3`,
    [req.session.tenantId, `%${input.q}%`, (input.page - 1) * 50]
  );
  res.json(result.rows);
});
```

Two reasons to validate even though parameters are bound:

1. **Schema mismatch as an early warning.** A `q` longer than 100 chars or a `page` of `99999999999` is suspicious — log it.
2. **Defense-in-depth against future refactors.** Some innocent-looking change to the SQL might re-introduce interpolation; the bounded input keeps the blast radius small.

### Lint against string-concatenated SQL

```js
// eslint.config.js
import securityPlugin from 'eslint-plugin-security';
export default [{
  plugins: { security: securityPlugin },
  rules: {
    'security/detect-object-injection': 'warn',
    // Custom rule: disallow template literals containing the word SELECT/INSERT/UPDATE/DELETE
    // adjacent to ${...}
    'no-restricted-syntax': ['error', {
      selector: "TemplateLiteral[expressions.length>0] > TemplateElement[value.raw=/\\b(select|insert|update|delete|drop|union)\\b/i]",
      message: 'Do not interpolate values into SQL strings. Use parameter binding ($1, $2).',
    }],
  },
}];
```

## What NOT to do

- ❌ **Don't** use `escape()` libraries as your primary defense. They can be bypassed; parameter binding cannot.
- ❌ **Don't** trust ORMs blindly. Most ORMs let you drop down to raw SQL with `db.raw(...)`, and some methods (`whereRaw`, `orderByRaw`) accept interpolation. Audit those calls.
- ❌ **Don't** sanitize by removing characters. `'; DROP TABLE--` becomes `DROP TABLE--` after stripping `;'`, which is still hostile.
- ❌ **Don't** allow user-supplied column names or `ORDER BY` directions as raw input. Whitelist them.

### The `ORDER BY` trap

```ts
// 🚨 user can sort by anything, including subqueries in some drivers
const sql = `SELECT * FROM customers ORDER BY ${req.query.sort}`;
```

Fix with an explicit allow-list:

```ts
const ALLOWED_SORTS = { name: 'name', created: 'created_at' } as const;
const sortKey = ALLOWED_SORTS[req.query.sort as keyof typeof ALLOWED_SORTS] ?? 'created_at';
const sql = `SELECT * FROM customers ORDER BY ${sortKey}`;
```

You map the user-supplied string to a known-safe column name. The user's input never ends up in the SQL itself.

## Beyond SQL: the same bug in other shells

| Surface | Vulnerable | Fix |
|---|---|---|
| Shell commands | `exec(\`grep ${user} log.txt\`)` | `execFile('grep', [user, 'log.txt'])` |
| MongoDB | `Customers.find({ name: req.query.q })` (operator injection: `?q[$ne]=` reads everything) | Validate with Zod that `q` is a string, not an object |
| LDAP | `(&(uid=${user}))` | Encode with an LDAP-aware library |
| XPath | `//user[@id='${id}']` | Use the parameterized API of your XPath library |
| Server-side templates | `eval(req.body.expr)` for "calculations" | Don't. There is no safe `eval`. |
| Regex (ReDoS) | User-controlled regex against unbounded input | Cap input length; consider [`safe-regex`](https://www.npmjs.com/package/safe-regex). |

## The test that catches the bad version

```ts
test('SQL injection through search query is impossible', async () => {
  await seed({ customers: [{ name: "Acme" }, { name: "Beta" }] });
  const session = await login();

  // The classic payload — should match nothing because it's treated as data, not code:
  const res = await request().get(`/api/search?q=' OR '1'='1`)
    .set('Cookie', session.cookie);
  expect(res.status).toBe(200);
  expect(res.body.length).toBe(0);   // no row has the literal name "' OR '1'='1"
});

test('UNION attack against search returns no rows', async () => {
  const session = await login();
  const payload = `' UNION SELECT id, password_hash FROM users--`;
  const res = await request().get(`/api/search?q=${encodeURIComponent(payload)}`)
    .set('Cookie', session.cookie);
  expect(res.status).toBe(200);
  // Result should be a normal empty list, not 0 rows of a 2-column UNION result that contained password_hash.
  for (const row of res.body) {
    expect(row).not.toHaveProperty('password_hash');
  }
});
```

## Pitfalls I've seen in production reviews

| Pitfall | Why |
|---|---|
| `LIKE` patterns built from user input | If you wrap with `%${q}%`, escape `%` and `_` in `q` first, or you get unintended matches and slow scans. |
| Raw `IN` lists from arrays | `WHERE id IN (${ids.join(',')})` — use `WHERE id = ANY($1::int[])` instead. |
| Type confusion via JS `==` | `req.query.id == 5` is true for `'5abc'` in some flows. Use Zod / strict parse. |
| Stored procedures with EXEC inside | Same rule applies. Procedures aren't a safety blanket. |
| Logging the bound query before binding | Logs become its own injection sink; redact. |

## Related chapters

- [A04 Insecure Design](./04-insecure-design.md) — schema design that reduces the attack surface for injection.
- [A05 Security Misconfiguration](./05-security-misconfiguration.md) — disable unsafe SQL features (e.g., `pg_read_server_files`).
- [A09 Logging & Monitoring Failures](./09-logging-monitoring.md) — alerting on Zod parse failures is a cheap, high-signal injection-attempt detector.

## References

- [OWASP A03:2021 — Injection](https://owasp.org/Top10/A03_2021-Injection/)
- [Bobby Tables](https://bobby-tables.com/) — the canonical reference, in a pithy form.
