# A05 Security Misconfiguration

> The bugs aren't in your code. They're in the defaults you didn't override.

## High-impact, low-effort wins

### HTTP security headers

Use [Helmet](https://helmetjs.github.io/) and configure CSP carefully:

```ts
import helmet from 'helmet';

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],            // no 'unsafe-inline', no 'unsafe-eval'
      styleSrc: ["'self'"],             // (use a hash if you must inline)
      imgSrc: ["'self'", 'data:'],
      connectSrc: ["'self'", 'https://api.stripe.com'],
      frameAncestors: ["'none'"],       // X-Frame-Options DENY
      objectSrc: ["'none'"],
      baseUri: ["'self'"],
      formAction: ["'self'"],
      upgradeInsecureRequests: [],
    },
  },
  hsts: { maxAge: 31536000, includeSubDomains: true, preload: true },
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
  permittedCrossDomainPolicies: false,
}));
```

Test: [Mozilla Observatory](https://observatory.mozilla.org/), [securityheaders.com](https://securityheaders.com).

### Production error responses

Never return stack traces or internal paths to clients in production:

```ts
app.use((err, req, res, next) => {
  const id = randomBase64(8);
  log.error({ id, err, path: req.path });
  if (process.env.NODE_ENV === 'production') {
    return res.status(500).json({ error: 'internal_error', request_id: id });
  }
  return res.status(500).json({ error: err.message, stack: err.stack, request_id: id });
});
```

The `request_id` lets support correlate without needing to expose internals.

### Disable defaults you don't use

- `X-Powered-By: Express` — disable (`app.disable('x-powered-by')`).
- Verbose `Server` headers from your reverse proxy.
- Default credentials anywhere (databases, admin UIs, dev tools).
- Sample apps and dev tooling baked into the production image.

### Boot-fail on missing config

```ts
import { z } from 'zod';

const Env = z.object({
  DATABASE_URL: z.string().url(),
  JWT_SECRET: z.string().min(32),
  STRIPE_WEBHOOK_SECRET: z.string().min(1),
  // ...
});

export const env = Env.parse(process.env);   // throws on boot if missing
```

The application that won't boot without secrets is the application that doesn't ship with placeholder secrets.

### Lock down CORS

```ts
import cors from 'cors';
app.use(cors({
  origin: process.env.ALLOWED_ORIGINS!.split(','),
  credentials: true,
}));
```

`origin: '*'` plus `credentials: true` is unsafe — and silently doesn't work in modern browsers, which can hide the misconfiguration.

## Cloud / IaC defaults to flip

| Service | Default to change |
|---|---|
| AWS S3 | Block all public access; set on bucket + account level. |
| AWS IAM | Refuse `*` resource on policies. Use `aws:PrincipalOrgID` conditions. |
| Azure Storage | Disable public blob access by default. |
| Postgres | Disable `pg_read_server_files` / `pg_read_server_files_to_text` for app roles. |
| Supabase | Use the **service_role** key only server-side, **anon** key client-side. Never confuse them. |
| Vercel | Don't expose env vars with `NEXT_PUBLIC_` prefix unless you mean them to be public. |

## What NOT to do

- ❌ **Don't** copy security configs from blog posts without reading them. CSP in particular has subtle implications (e.g., Stripe.js needs `script-src` allowance).
- ❌ **Don't** disable security headers "to debug." If you must, do it locally and never in production.
- ❌ **Don't** treat infrastructure as separate from app security. The `*` IAM policy is also a misconfiguration.

## References

- [OWASP A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/)
- [Mozilla Observatory](https://observatory.mozilla.org/)
- [Helmet documentation](https://helmetjs.github.io/)
