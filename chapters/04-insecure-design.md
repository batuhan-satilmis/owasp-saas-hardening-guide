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

## What NOT to do

- ❌ **Don't** treat security review as a one-time pre-launch event. Things change.
- ❌ **Don't** rely on "we'll add it later." It's harder later.
- ❌ **Don't** assume happy-path. The attacker is testing every edge of every input you didn't think to test.

## References

- [OWASP A04:2021](https://owasp.org/Top10/A04_2021-Insecure_Design/)
- [Threat modeling repo](https://github.com/batuhan-satilmis/threat-modeling-framework)
