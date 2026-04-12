# FAQ

## General

**What is FlareInspect?**
FlareInspect is a CLI tool and web dashboard that assesses Cloudflare accounts
and zones for security configuration issues, maps findings to compliance
frameworks, and exports reports in multiple formats.

**Who built FlareInspect?**
FlareInspect is built by IONSEC.IO, a cloud security company.

**Is FlareInspect free?**
Yes, FlareInspect is open source under the MIT license.

## Assessment

**How long does an assessment take?**
Depends on the number of zones and the concurrency setting. A typical
single-zone assessment completes in under 30 seconds. Use `--concurrency` to
parallelize multi-zone assessments.

**Does FlareInspect make any changes to my Cloudflare account?**
No. FlareInspect only reads configuration via the Cloudflare API. It never
modifies or writes to your account.

**What if my token can only see one zone?**
FlareInspect will assess only the zones visible to the token. If the token is
scoped to a single zone, only that zone is assessed.

**Can I assess multiple Cloudflare accounts?**
Run separate assessments with tokens scoped to each account.

## Scoring

**How is the security score calculated?**
The score is a weighted pass rate: `(passedWeight / totalWeight) × 100`, where
weights correspond to severity (critical=10, high=7, medium=4, low=2,
informational=1).

**What is contextual scoring?**
Contextual scoring adjusts severity based on the zone's Cloudflare plan, data
sensitivity, and exposure level. Use `--sensitivity` to enable it.

## Compliance

**Which frameworks are supported?**
CIS, SOC 2, PCI-DSS, and NIST CSF. Use `--compliance <framework>`.

**Are the compliance mappings officially certified?**
No. FlareInspect provides mapping to common framework controls for reference.
Organizations should validate mappings against their own compliance
requirements.

## Deployment

**Can I run FlareInspect in production?**
Yes, via Docker or the web dashboard. See the [Deployment](deployment/docker.md)
section for guidance.

**How do I secure the web dashboard?**
Set `FLAREINSPECT_API_KEY` for API authentication, bind to `127.0.0.1`, and
use a reverse proxy with TLS. See [Authentication](web-dashboard/authentication.md).
