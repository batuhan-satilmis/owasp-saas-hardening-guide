# A06 Vulnerable & Outdated Components

> Most modern apps are 90% other people's code. The supply-chain attack is now a higher-probability event than the bespoke-bug attack.

## What good looks like

### Continuous dependency monitoring

```yaml
# .github/dependabot.yml
version: 2
updates:
  - package-ecosystem: "npm"
    directory: "/"
    schedule:
      interval: "weekly"
    open-pull-requests-limit: 10
    groups:
      minor-and-patch:
        update-types:
          - "minor"
          - "patch"
```

Dependabot or [Renovate](https://github.com/renovatebot/renovate) opens PRs. Group minor+patch into a single PR per week to reduce noise; treat majors as their own decision.

### CI gate

```yaml
# .github/workflows/security.yml
- run: npm audit --audit-level=high
```

Fail the build on high/critical vulns. For dev-only deps, accept moderate. Don't accept high in anything that runs in production.

### Generate an SBOM on every release

```yaml
- run: npx @cyclonedx/bom -o sbom.json
- uses: actions/upload-artifact@v4
  with:
    name: sbom
    path: sbom.json
```

CycloneDX or SPDX. Attach to the release. When the next Log4j-class CVE drops, you'll be glad you can answer "are we affected?" in minutes, not days.

### Static + transitive scanning

- **`npm audit`** — surface-level.
- **[Socket](https://socket.dev/)** or **Snyk** — transitive + behavioral analysis (catches malicious packages, not just CVEs).
- **[OSV-Scanner](https://github.com/google/osv-scanner)** — Google's open-source vulnerability scanner across many ecosystems.

## Lockfile hygiene

- Always commit the lockfile (`package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`).
- Use `npm ci` in CI (strict — fails on lockfile drift).
- Pin Docker base images by digest, not just tag.

## Subresource Integrity for CDN scripts

If you load a script from a CDN, give it integrity hashes:

```html
<script src="https://cdn.example.com/lib.js"
        integrity="sha384-..."
        crossorigin="anonymous"></script>
```

A compromised CDN serving a different file fails the hash check; the browser refuses to run it. This is *especially* important for analytics, payments, and chat widgets.

## What NOT to do

- ❌ **Don't** vendor random packages with low download counts and no maintainer activity. Read the Socket / npm trustscore.
- ❌ **Don't** trust `latest` tags. Use a pinned version.
- ❌ **Don't** skip `npm audit` because "fixing the deprecation warning is annoying." That's the bug.
- ❌ **Don't** install dev tooling globally with package-manager wrappers that download arbitrary scripts. Use scoped, pinned versions.

## References

- [OWASP A06:2021](https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/)
- [CISA SBOM resources](https://www.cisa.gov/sbom)
- [Socket](https://socket.dev/) · [OSV-Scanner](https://github.com/google/osv-scanner)
