# TODO

NFR gaps found 2026-09-20 auditing the public web surface against
`/Users/alex/dev/2026/NFR-and-Repetitive-Specs`. PAGE-002 and PAGE-003 are
**Proposed**, not Adopted, so these are followed unless you decide otherwise.

## Support page (PAGE-003) — absent entirely

- [ ] Add a `/support` route. Nothing exists today: no route, no form, no endpoint.
- [ ] Four addressable states: form (`GET /support`), parked (`POST /support`),
      inert confirm (`GET` renders a button, only `POST /support/confirm` relays),
      sent.
- [ ] `GET /support/confirm` must mutate nothing. A relaying GET is silently
      defeated by corporate link scanners that auto-fetch inbound mail.
- [ ] Confirm mail from `no-reply@sp33c.tech`; relay to `info@sp33c.tech` with
      `Reply-To` set to the submitter.
- [ ] Rate limit `POST /support` by IP and IP+email; honeypot field; reject
      `[\r\n,;<>]` in the address server-side before it reaches SES.
- [ ] Store only `sha256(token)` with a 24h epoch-second TTL, consumed atomically
      and once, constant-time compare, one generic failure message.
- [ ] Identical copy, status and timing for known and unknown addresses (SEC-005).

## Imprint (PAGE-002) — content is there, the route is not

- [ ] Serve the imprint at a stable `/imprint` path. It is currently only an
      anchor section (`#imprint`) on the landing page, and the router's catch-all
      redirects `/imprint` to `/`.
- [ ] `/impressum` must resolve to the same content, never 404.
- [ ] Reachable when the landing page is off. `flags.landing = false` makes `/`
      the login page, and the imprint becomes unreachable.
- [ ] Add the second means of direct contact required by §8. Only email is
      listed today. The `/support` form satisfies this, so the two are coupled.
- [ ] Add the §36 VSBG consumer dispute-resolution statement if selling to consumers.
- [ ] Single exported `IMPRINT_URL` / `SUPPORT_URL` / `PRIVACY_URL` constant
      feeding footer and any store metadata, rather than inline hrefs.
- [ ] Privacy and imprint must be separate pages that link each other. Privacy is
      currently an outbound link to `sp33c.tech/datenschutz.html` only.

## Privacy page (PAGE-001) — no route, only an outbound link

- [ ] Serve a `/privacy` route. There is none. The landing imprint block links out
      to `sp33c.tech/datenschutz.html` instead (`web/src/pages/LandingPage.tsx:262`).
- [ ] Content must match the shipped system: controller, what is collected and why,
      lawful basis, retention, processors, user rights, tracking posture.
- [ ] Retention statement must match the real TTLs. The OTP table expires rows at
      600s via `expiresAt` (`infra/sst.config.ts:88`,
      `infra/functions/auth/request.ts:10`). The AccessTable has no TTL.
- [ ] Visible "last updated" date that changes with the copy.
- [ ] Name a working way to exercise erasure, access and export. Route these
      through `/support` rather than adding a second public write endpoint.
- [ ] Link privacy and imprint to each other as siblings.

## Google Fonts is a third-party call before any consent (PAGE-001 §16) — DONE

- [x] Removed the `fonts.googleapis.com` / `fonts.gstatic.com` links from
      `web/index.html` and imported the same faces and weights from
      `@fontsource/ibm-plex-sans` and `@fontsource/ibm-plex-mono` in
      `web/src/main.tsx`. Verified: `npm run build` emits the woff2 files locally
      and `grep` finds no Google host anywhere in `dist/`.

## Footer is not unified (UI-008)

- [ ] The footer exists only on the landing page
      (`web/src/pages/LandingPage.tsx:272`). The login page and the whole
      signed-in shell (`web/src/App.tsx:23-48`) render no footer at all.
- [ ] It must carry imprint, privacy and support links on every page, as real
      links, reachable signed-out.

## Page metadata (SEO-003)

- [ ] `web/index.html:6` has one static title and no description, canonical URL,
      or social card tags. An SPA needs per-route metadata once `/imprint`,
      `/privacy` and `/support` exist.

## SEO baseline (SEO-001, SEO-002) — no static assets at all

- [ ] No `web/public/` directory, so no `robots.txt` and no `sitemap.xml`.
- [ ] Keep indexing posture consistent once `/imprint` and `/support` exist, and
      do not `Disallow` the imprint. Non-production stages must be `noindex`.

## Signup — absent by design, needs a product decision

The app is invite-only. `infra/functions/auth/request.ts` mails a code only when
`isKnownUser()` passes, which covers bootstrap admins in `adminEmails` plus
anyone already holding a project or team membership. There is no registration
route, endpoint or UI, and the landing footer advertises "invite-only".

- [ ] Decide whether self-service signup is actually wanted. It is not a
      regression to fix, it is a change of posture, and it interacts with the
      enumeration-resistant generic login response (SEC-005) and with who is
      allowed to create the first project.

## Hardening decisions (agreed 2026-09-20)

- [x] **Lock CORS before production.** Done. `infra/sst.config.ts` now takes
      browser origins from a per-stage `webOrigins` map, used by both the API and
      the vault bucket. `dev` stays wildcard. A production deploy with no origin
      configured refuses to run unless bootstrapped with
      `ENCLAVE_BOOTSTRAP_CORS=1`, which exists only because the CloudFront domain
      does not exist before the first deploy. Fill in `webOrigins.production` and
      redeploy without the variable.
- [x] **Edge rate limiting.** Done in code, not yet deployed. The API is now an
      origin on the site CloudFront distribution under `/api`, so a
      CloudFront-scoped Web ACL (us-east-1, production only) can see it. Two
      per-IP rules: a broad flood backstop and a tighter one on `POST /api/*`.
      `functions/lib/edge.ts` rejects any request that did not arrive through
      CloudFront, so the raw execute-api URL cannot bypass the Web ACL.
- [x] **Verify the edge path against a real deploy.** Done 2026-09-20. Both
      stages deployed. `POST /api/auth/request` and `GET /api/access/whoami`
      answer correctly through CloudFront on dev and production, and the Web ACL
      is attached to the production distribution
      (`arn:aws:wafv2:us-east-1:327261196437:global/webacl/EdgeAcl-113b2bc/...`).
- [ ] **Close the origin bypass on production.** `EdgeOriginToken` is still
      unset, so `functions/lib/edge.ts` fails open and the raw
      `https://yd66xzv0g6.execute-api.eu-central-1.amazonaws.com/api/...` still
      answers 200, skipping the Web ACL entirely. Verified on 2026-09-20.
      Closing it is `sst secret set EdgeOriginToken` plus a redeploy. Expect a
      short window where the Lambdas require the header before the CloudFront
      distribution finishes propagating it, so do it deliberately, not mid-day.
- [ ] **Reconfigure CLI installs.** API routes moved under `/api` on both
      stages. `enclave configure --api-url` now takes the `ApiUrl` output
      (`<SiteUrl>/api`), not the execute-api URL.
- [ ] **enclavecore.app: finish the delegation.** Route 53 public hosted zone
      created 2026-09-20, `Z05132714ZL2SHERUCOL`.

      Diagnosed 2026-09-20: this is NOT propagation lag. The `.app` registry
      itself still returns `ns1.vercel-dns.com` / `ns2.vercel-dns.com`, so the
      change was never saved. The domain is registered **at Vercel**, under the
      team "Alex Fitterling's projects"
      (`team_1fRqUIndZfyYON3mDWbdxVhr`), and its record has no
      `customNameservers` field at all — unlike finwise.social, tallyloop.app,
      worldteamclock.app, lucernapdf.app, purchaselist.app, sohalearn.com and
      nutritionwithlove.app, which all carry an AWS `customNameservers` array.

      Fix it in the Vercel dashboard: the domain's Custom Nameservers setting,
      same place as the other seven. The Vercel API integration available here
      exposes no tool for that field. Set these four:

          ns-356.awsdns-44.com
          ns-618.awsdns-13.net
          ns-1261.awsdns-29.org
          ns-1680.awsdns-18.co.uk

      Note this takes the domain off Vercel. Before the switch it served A
      records at the apex (216.150.16.129, 216.150.16.1) and at www
      (216.150.16.65, 216.150.1.129). There were no MX and no TXT records, so
      no mail or domain-verification records are at risk.
- [ ] **Then enable the domain.** Once `dig NS enclavecore.app` returns the AWS
      nameservers, uncomment `siteDomains.production` in `infra/sst.config.ts`
      and redeploy. SST creates the ACM certificate and the validation records
      in the zone. Doing it before delegation propagates hangs the deploy on
      certificate validation. The CORS origin list already names both the
      CloudFront domain and the custom one, so uploads keep working across the
      cutover.
- [ ] **Harden the support route at build time**, not afterwards: honeypot,
      per-IP and per-IP-plus-email limits, server-side rejection of
      `[\r\n,;<>]` in the address, `sha256(token)` only, 24h epoch-second TTL,
      atomic single-use consumption, constant-time compare, one generic failure
      message. Tracked in the support section above.
