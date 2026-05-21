# A10 Server-Side Request Forgery

> Your server fetches a URL. The URL is supplied by an attacker. The attacker now uses your server as a proxy into your private network.

## What it looks like

```ts
// vulnerable.ts — "import an image from a URL"
app.post('/api/avatar/import', async (req, res) => {
  const url = req.body.url;
  const data = await fetch(url);             // 🚨
  const buf = await data.arrayBuffer();
  await uploadToStorage(buf);
  res.sendStatus(200);
});
```

Why bad: the attacker can pass `http://169.254.169.254/latest/meta-data/iam/security-credentials/` (the AWS metadata endpoint) and exfiltrate cloud creds. Or `http://localhost:6379/` (Redis without auth). Or a URL inside your private VPC that's only accessible from the server.

## The fix

### 1. Resolve DNS server-side, then validate the resolved IP

```ts
import { lookup } from 'node:dns/promises';
import ipaddr from 'ipaddr.js';

async function isUrlSafe(rawUrl: string): Promise<boolean> {
  let url: URL;
  try { url = new URL(rawUrl); } catch { return false; }
  if (url.protocol !== 'https:') return false;

  const { address } = await lookup(url.hostname);
  const ip = ipaddr.parse(address);

  // Reject private, link-local, loopback, broadcast, CGNAT, etc.
  const range = ip.range();
  return range === 'unicast';     // public IPs only
}
```

This rejects:
- `127.0.0.1`, `::1` (loopback)
- `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` (private)
- `169.254.0.0/16` (link-local — including AWS metadata)
- `100.64.0.0/10` (CGNAT)
- IPv6 unique-local

### 2. Allow-list domains where possible

```ts
const ALLOWED_HOSTS = new Set([
  'images.example-cdn.com',
  'cdn.acme.com',
]);

if (!ALLOWED_HOSTS.has(url.hostname)) return res.status(400).end();
```

### 3. Disable redirects

```ts
const data = await fetch(rawUrl, { redirect: 'manual' });
```

Otherwise an attacker hosts `https://evil.com/redirect-to-internal.php` that 302s to `http://169.254.169.254/...`.

### 4. Use a separate egress identity

If your app calls external services *and* internal services from the same host, an SSRF that lands on internal services has more reach. Some teams put outbound HTTP for user-supplied URLs through a separate, network-restricted egress proxy that can only reach the public internet.

### 5. Defeat DNS rebinding (TOCTOU between resolve and connect)

The pattern in step 1 has a subtle race condition: between `lookup(url.hostname)` and `fetch(rawUrl)`, the application performs **two** DNS resolutions — once to validate, and a second time when the HTTP client actually connects. An attacker who controls the authoritative DNS for `evil.example` can answer the first query with a public IP (passes the unicast check) and the second query with `169.254.169.254`. The TTL on the malicious record is 0; both resolves are live.

```ts
// 🚨 still vulnerable — the URL is re-resolved by fetch()
if (await isUrlSafe(rawUrl)) {
  const data = await fetch(rawUrl);   // resolves the hostname again
}
```

This is **DNS rebinding**, and a public PoC has existed since [the 2017 Tavis Ormandy disclosures](https://bugs.chromium.org/p/project-zero/issues/detail?id=1471). It bypasses every IP-based allow-list that does the check ahead of the connection.

The fix: resolve **once**, then connect to that exact IP — and carry the original hostname in the `Host` header so TLS / virtual hosting still works.

```ts
import { Agent } from 'undici';
import { lookup } from 'node:dns/promises';

async function safeFetch(rawUrl: string): Promise<Response> {
  const url = new URL(rawUrl);
  if (url.protocol !== 'https:') throw new Error('https only');

  const { address: ip } = await lookup(url.hostname);
  if (ipaddr.parse(ip).range() !== 'unicast') {
    throw new Error('resolved to a non-public address');
  }

  // Pin the connection to the IP we validated. The TLS handshake still uses
  // the original hostname (SNI + cert verification), so we don't lose auth.
  const agent = new Agent({
    connect: { lookup: (_host, _opts, cb) => cb(null, ip, 4) },
  });

  return fetch(rawUrl, { dispatcher: agent, redirect: 'manual' });
}
```

What this buys you:

- Only **one** DNS resolution is observed by the attacker's authoritative server, so they cannot serve two different answers.
- TLS certificate verification still binds to `url.hostname`, not to the IP — a rogue cert for `169.254.169.254` does not help the attacker.
- Pairs naturally with the redirect-disabling rule in step 3 (without it, a 302 to a fresh hostname re-opens the rebinding window).

### The test that catches the bad version

```ts
test('rebinding attack: DNS that returns public IP then internal is rejected', async () => {
  // Mock the resolver so the first call returns a public IP and any
  // subsequent call returns a link-local one. The vulnerable code path
  // would call lookup() twice and pass validation on the first.
  let call = 0;
  vi.spyOn(dnsPromises, 'lookup').mockImplementation(async () => ({
    address: (++call === 1) ? '93.184.216.34' : '169.254.169.254',
    family: 4,
  }));

  // safeFetch resolves exactly once and pins the connection.
  await expect(safeFetch('https://rebind.evil.test/x')).resolves.toBeDefined();
  expect(call).toBe(1);                            // only one lookup happened
});
```


## Cloud-specific gotchas

- **AWS IMDSv2** is much harder to SSRF than v1 because it requires a session token. Enforce `instance-metadata-options: HttpTokens=required`.
- **GCP metadata** requires the `Metadata-Flavor: Google` header, but a `fetch()` call that lets the user control headers may set it.
- **Azure metadata** requires `Metadata: true` header.

## What NOT to do

- ❌ **Don't** rely on string blacklists like "block `localhost`". `127.0.1.1`, `0.0.0.0`, `[::ffff:127.0.0.1]`, decimal-encoded IPs all bypass naive checks.
- ❌ **Don't** check the URL string alone. Resolve DNS server-side.
- ❌ **Don't** allow user-supplied protocols. `gopher://`, `file://`, `dict://` are exploitation primitives.

## References

- [OWASP A10:2021](https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/)
- [OWASP SSRF Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
- [Capital One breach root-cause](https://krebsonsecurity.com/2019/08/what-we-can-learn-from-the-capital-one-hack/) — SSRF + IMDSv1 + over-privileged role.
