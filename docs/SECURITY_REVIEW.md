# WatchMe — Basic security review

Scope: the whole source tree (`server/`, `server.ts`, `src/`, `tools/`), reviewed on 2026-09-29 against WatchMe 0.8.0. This is a **basic** review — a manual read of the security-relevant code plus dependency and pattern scans, not a formal pen-test or a guarantee of no vulnerabilities.

## How it was checked

- `npm audit` (prod and full dependency tree).
- Grep for dangerous sinks: `eval`, `new Function`, `child_process`/`exec`/`spawn`, `dangerouslySetInnerHTML`, `innerHTML`.
- Manual read of every Express route in `server.ts`, the data adapters (`server/elastic.ts`, `server/splunk.ts`), the store (`server/store.ts`), the AI/sanitize path (`server/ai.ts`, `server/sanitize.ts`, `server/storyline.ts`), and secret/TLS handling.
- Injection review: SQL, Elasticsearch/Lucene, Splunk SPL, prototype pollution, XSS, SSRF, ReDoS.

## Clean results (no action needed)

- **Dependencies:** `npm audit` reports **0 vulnerabilities** (prod and dev).
- **No dangerous sinks:** no `eval`, `new Function`, `child_process`, or `dangerouslySetInnerHTML`/`innerHTML` anywhere in `server/` or `src/`. AI-generated markdown is rendered as text/markdown, not raw HTML, so no stored/reflected XSS via case summaries or storylines.
- **SQL is fully parameterized** (`server/store.ts`): every query uses `$1,$2,…` placeholders via `pg`; no string-concatenated SQL. The dynamic `WHERE` in `listNotes` builds only placeholder positions, not values.
- **Prototype pollution is guarded:** `/api/admin/config` validates every `riskWeights` key against a fixed whitelist (`RISK_WEIGHT_KEYS`) and rejects unknown keys, so `__proto__`/`constructor` can't be written. No other route does `obj[userKey] = value` with client-controlled keys.
- **TLS verification is on by default** for both Elastic and Splunk (`*_VERIFY_TLS !== 'false'`).
- **Secrets are not committed and not leaked:** credentials come only from env; `.env*` is gitignored (only `.env.example` is tracked); `/api/status` and `/api/admin/config` return endpoints and labels but never passwords/API keys.
- **Webhook secret check is timing-safe** (`crypto.timingSafeEqual`, length-guarded).

## What was fixed in 0.8.1

- **#2 (Host / CSRF / DNS-rebinding):** added security middleware in `server.ts` — a **Host-header allow-list** (localhost/`127.0.0.1`/`::1`, the bound interface, or anything in `ALLOWED_HOSTS`) and an **Origin/Referer same-origin guard** on all state-changing methods (POST/PUT/PATCH/DELETE). Cross-site and rebinding requests now get `403`.
- **#5 (unbounded profile):** both AI endpoints now validate the profile through `requireProfile()`, which caps it at 5,000 nodes / 20,000 edges (`413` otherwise) before any regex work.
- **#6 (error leakage):** the global error handler now returns a generic `"Internal server error"` for 5xx; details stay in the server log. Intentional 4xx messages are still returned.

Not changed by design: **#1** (no user login) and **#3** (privileged query console) — these are inherent to a local single-analyst tool. The guards above make the default localhost posture safe against browser-based attacks; real user authentication is still required before binding beyond localhost. **#4** (TLS verify) is already secure by default.

## Findings

Severities assume the **default** posture (bound to `127.0.0.1`, single local analyst). Several rise sharply if the app is exposed on a LAN/0.0.0.0.

### 1. No server-side authentication — the sign-in page is cosmetic — Medium (High if exposed)
The new sign-in screen is **client-side only**: it flips a `localStorage` flag (`watchme-authed`) and renders the app. The server (`server.ts`) has **no auth on any `/api/*` route**. Anyone who can reach the port has full access: read every user's graph, create/close cases, ingest alerts, run backend SIEM queries, change admin config.

Mitigated today by `HOST` defaulting to `127.0.0.1`. It becomes **High** the moment someone sets `HOST=0.0.0.0` (or runs behind a reverse proxy) expecting the login page to protect them — it does not.

**Recommend:** keep the demo login clearly labelled as a demo (already done). Before any non-localhost deployment, add real auth (a reverse proxy with SSO, or session middleware) and enforce it server-side. Document that the login is not a security control.

### 2. No CSRF / Host-header / DNS-rebinding protection — Medium
There is no CORS config, no CSRF token, and no `Host`-header allowlist. A malicious website the analyst visits could attempt requests to `http://127.0.0.1:3000/api/*` (state-changing: add watchlist entries, create cases, ingest alerts, run queries).

Partly mitigated because the API only accepts `application/json` bodies and sets no CORS headers, so a cross-origin `fetch` triggers a preflight the browser blocks. **DNS rebinding** defeats that mitigation (the request then looks same-origin).

**Recommend:** add a small middleware that rejects requests whose `Host` header isn't `127.0.0.1:PORT`/`localhost:PORT`. Cheap, and it closes the DNS-rebinding path.

### 3. Ad-hoc query console forwards arbitrary queries to the backend SIEM — Low (Medium if exposed)
`/api/integrations/query` (and graph search/expand) pass a client-supplied string straight into Elasticsearch `query_string` / Splunk SPL, executed with the **server's** stored credentials. This is an intended analyst feature and is constrained to the configured index and the requested time window. But with finding #1, anyone reaching the API can run arbitrary backend queries (broad data reads, expensive queries → load).

**Recommend:** treat this as privileged; gate it behind the auth from #1. Optionally cap result size / time window server-side (a `maxEvents` cap already exists for the graph path).

### 4. TLS verification can be disabled by env — Low
`ELASTIC_VERIFY_TLS=false` / `SPLUNK_VERIFY_TLS=false` turn off certificate verification (MITM risk on the SIEM connection). Default is secure (on).

**Recommend:** keep the default; document that `false` is lab-only and never for production creds.

### 5. Unbounded client `profile` in the AI endpoints — CPU DoS — Low
`/api/gemini/case-summary` and `/api/ai/storyline` accept a client-supplied `profile` up to the 5 MB JSON limit. `tokenizeProfile` builds a regex per entity name and runs them over the graph facts, so a crafted profile with a very large `nodes` array can burn CPU. Localhost + no auth makes this low priority, but it's a cheap hardening win.

**Recommend:** cap `profile.nodes`/`profile.edges` length (e.g. reject > a few thousand) at the top of both handlers, alongside the existing array-type check.

### 6. Error responses echo `err.message` — Low / informational
The global error handler returns `err.message` to the client (stack traces are only `console.error`'d, and 5xx is logged). Minor internal-detail disclosure. Acceptable for a local tool; revisit if exposed.

## Bottom line

For its **intended** use — a local, single-analyst, `127.0.0.1` investigation console — the code is in good shape: no injectable SQL, no unsafe HTML, no committed secrets, patched dependencies. The meaningful risks are all about **exposure beyond localhost**: the app has no real authentication (the login page is a demo), and no CSRF/DNS-rebinding guard. Add the Host-header check (#2) now as cheap defense-in-depth, and require real auth (#1) before ever binding to anything other than localhost.
