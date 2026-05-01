# A09 Security Logging & Monitoring Failures

> Most breaches are *detected* months after they happen. The fix is two-part: log the right things, and alert on the right patterns.

## What to log

| Event | Why |
|---|---|
| Auth: login success/failure | Detection of credential stuffing, account takeover. |
| Auth: refresh-token reuse detected | High-signal compromise indicator (see [chapter 7](./07-identification-authentication.md)). |
| Privileged actions | Audit / compliance. Includes invites, role changes, billing changes, exports, deletions. |
| Authorization failures | A 403 spike from one IP across many endpoints == reconnaissance. |
| Schema validation failures (Zod parse errors) | Cheap injection-attempt detector. |
| Webhook signature mismatches | Forgery attempts. |
| Rate-limit triggers | Abuse / scraping. |

## What NOT to log

- ❌ Passwords (in any form).
- ❌ Session IDs / tokens.
- ❌ JWTs (even though they can technically be public, logging them creates a credential leak risk).
- ❌ PII *values*. Log column *names* changed, not values.
- ❌ Request bodies in their entirety. Log keys, omit values, redact known-sensitive keys.

```ts
function redact(body: unknown): unknown {
  const SENSITIVE = /password|token|secret|ssn|card|cvv/i;
  if (typeof body !== 'object' || !body) return body;
  return Object.fromEntries(
    Object.entries(body as Record<string, unknown>).map(
      ([k, v]) => SENSITIVE.test(k) ? [k, '[REDACTED]'] : [k, v]
    )
  );
}
```

## Append-only audit log pattern

```sql
CREATE TABLE audit_log (
  id          bigserial PRIMARY KEY,
  occurred_at timestamptz NOT NULL DEFAULT now(),
  actor_id    uuid,
  tenant_id   uuid,
  event       text NOT NULL,
  resource    text,
  before      jsonb,
  after       jsonb,
  ip          inet,
  user_agent  text
);

-- The application role used by the API:
GRANT INSERT ON audit_log TO api_app_role;
-- Explicitly NOT granted: SELECT (handled by a separate read role), UPDATE, DELETE.
```

The application can write but not modify. The DB engineer / auditor uses a read-only role to query. Tampering requires a separate-account compromise.

## Alerting on the right patterns

| Alert | Pattern |
|---|---|
| Credential stuffing | One IP > N login failures across distinct emails in a short window. |
| Account takeover suspicion | Login from a new country + password change within 1 hour. |
| Recon | Single user/IP causes 403s across > N endpoints. |
| Token theft | `auth.refresh_reuse_detected` event (page immediately). |
| Webhook attack | Spike in webhook signature failures. |
| Mass export | One user exports > N records in < N minutes. |

The first three are easy to compute from access logs; the rest require structured events.

## Alert hygiene

- Every alert needs a documented runbook (see [incident-response-playbook](https://github.com/batuhan-satilmis/incident-response-playbook)). An alert without a runbook is noise.
- Track alert MTTA (mean time to acknowledge) and MTTR (mean time to resolve). If an alert fires and never gets acted on, retire it.
- Page only on things you'd wake an engineer for. Everything else goes to a chat/email digest.

## What NOT to do

- ❌ **Don't** ship logs to one place and hope you'll find what you need. Structured fields, indexed.
- ❌ **Don't** retain logs forever — that's its own data-protection problem. 90-180 days for app logs, longer for audit.
- ❌ **Don't** assume your provider's "audit log" feature replaces your application audit log. They're complementary; the app log knows your domain semantics.

## References

- [OWASP A09:2021](https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/)
- [NIST SP 800-92 — Guide to Computer Security Log Management](https://csrc.nist.gov/publications/detail/sp/800-92/final)
