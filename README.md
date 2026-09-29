# StoryLine

Identity-centric investigation tool for SOC analysts: pick a user, and WatchMe builds a graph of what that identity touched over the last 48 hours (or 7 days), scores it with explainable risk indicators, replays it on a timeline, exports the replay as video evidence, and writes a case summary.

## Quick start (demo data, no setup)

Prerequisite: Node.js 20 or later (Vite 6 is used so older Node 20 releases work).

```bash
npm install
npm run dev          # http://127.0.0.1:3000
```

Demo mode uses three fictional users (`jsmith`, `apatel`, `mross`). Everything is labelled **DEMO DATA** in the UI.

## Investigate real logs from Splunk

1. Start Splunk and PostgreSQL: `docker compose up -d` (or use an existing Splunk).
2. Load a dataset, for example Splunk BOTS v3, into an index such as `botsv3`.
3. Copy `.env.example` to `.env` and set:
   ```
   DATA_SOURCE=splunk
   SPLUNK_URL=https://localhost:8089
   SPLUNK_USERNAME=admin
   SPLUNK_PASSWORD=ChangeMe123!
   SPLUNK_VERIFY_TLS=false
   SPLUNK_INDEX=botsv3
   DEFAULT_T0=2018-08-21T00:00:00Z     # BOTS data is historical; pick the end of your window
   DATABASE_URL=postgres://watchme:watchme@localhost:5432/watchme
   ```
4. `npm run dev`, then type a username in the search box (Ctrl+K) and press Enter.

Splunk Free: if WatchMe runs on a different host than Splunk, add `allowRemoteLogin = always` under `[general]` in `$SPLUNK_HOME/etc/system/local/server.conf` and restart Splunk. Splunk Free has no user accounts, so keep it on an isolated network.

**No Splunk available?** `npm run mock:splunk` starts a mock of the Splunk REST API with a planted attack for user `bgist`. Use `SPLUNK_URL=http://127.0.0.1:8089`, `SPLUNK_USERNAME=admin`, `SPLUNK_PASSWORD=changeme`, `DEFAULT_T0=2018-08-21T00:00:00Z`.

## Live data from Elastic (free, on your own laptop)

Elasticsearch and Kibana run in Docker Desktop; Winlogbeat ships your Windows event logs (Security, Sysmon, PowerShell) into them. Full Windows walkthrough: [docs/ELASTIC_SETUP.md](docs/ELASTIC_SETUP.md).

```powershell
docker compose -f docker-compose.elastic.yml up -d     # Elasticsearch :9200 + Kibana :5601, localhost only
# install Winlogbeat 8.19.13 with tools/winlogbeat/winlogbeat.yml (see the guide)
```

`.env`:

```
DATA_SOURCE=elastic
ELASTIC_URL=http://localhost:9200
ELASTIC_USERNAME=elastic
ELASTIC_PASSWORD=changeme
ELASTIC_INDEX=winlogbeat-*
```

WatchMe reads ECS fields (Winlogbeat's ingest pipelines) and falls back to raw `winlog.event_data.*` fields. The query console uses Lucene syntax, e.g. `event.code:4625 AND user.name:"epbas"`.

**No Elastic available?** `npm run mock:elastic` starts a mock of the search API on port 9200 with a planted attack for user `epbas`, relative to the current time.

## Investigation features

- **Attack Path** (default): linear, time-ordered path with revisit tags, command summaries under process steps, and hover details.
- **AI Storyline**: attack phases with explanations; every step cites the evidence. Uses Gemini or a local Ollama model, or a rule-based fallback. Approve to freeze it into the case.
- **Relationship Graph** and **Event Timeline**.
- **Notes**: hypotheses, verdicts, assignment, closure and approvals (append-only).
- **Window bar**: the window is frozen after the first load; edit start/end, re-query, or switch to Live (30 s refresh).
- **Assign & Close**: disposition and closure notes, recorded on the case.
- **Search graphs**: build a graph from any log search (Integrations query console, Ctrl+K, or "Graph all activity on this host").

## How it works

```
Browser (React + canvas) ──> server.ts (Express API)
                                ├── server/sources.ts       LogSource interface: picks demo, Splunk or Elastic
                                ├── server/splunk.ts        SPL over /services/search/jobs/export
                                ├── server/elastic.ts       Elasticsearch _search (search_after, terms aggs)
                                ├── server/normalize.ts     Splunk: Windows Security, Sysmon, CIM -> one event shape
                                ├── server/normalizeEcs.ts  Elastic: ECS / Winlogbeat -> the same event shape
                                ├── server/graphBuilder.ts  events -> nodes, edges, milestones (opaque ids)
                                ├── server/risk.ts          explainable indicators (spec section 6)
                                ├── server/sanitize.ts      tokenization, citation audit, fallback summary
                                ├── server/ai.ts            AI provider: Gemini or Ollama (local)
                                ├── server/storyline.ts     AI Storyline: tokenized steps in, validated citations out
                                └── server/store.ts         PostgreSQL (DATABASE_URL) or in-memory
```

- **Query on demand.** WatchMe does not copy logs. Each investigation runs one search (SPL or Elasticsearch query) for the user's window plus one baseline search over the previous `BASELINE_DAYS` days. Results are cached for 5 minutes.
- **Risk indicators implemented:** brute force then success, first-seen host/app (x2 for crown jewels), new source IP, lateral fan-out, privilege change, mass file access, large upload, encoded PowerShell, correlated alerts. VIP and privileged multipliers apply. **Not yet implemented:** impossible travel (needs GeoIP), MFA fatigue (needs IdP MFA logs), off-hours activity (needs an activity profile).
- **Graph size:** capped at 400 nodes / 1,500 edges; the highest-risk edges are kept and the UI says when it is truncated.
- **AI summary:** with `GEMINI_API_KEY` set, the model receives only tokenized graph facts (USER_1, HOST_2 ...). Names, IPs, emails, paths and account names are scrubbed from free text, and names are restored server-side after the response. Every summary gets a citation check. Without a key, a deterministic summary is built from the graph. The Privacy Inspector shows the exact payload.
- **Replay evidence:** recorded in the browser with MediaRecorder (MP4 in Chrome/Edge, WebM in Firefox). The SHA-256 is computed over the exact file bytes and can be registered with the case, which records it in the audit log.
- **Audit log:** every view, search, export, summary, approval and simulated action is recorded. In PostgreSQL the table is append-only (UPDATE and DELETE are blocked by a trigger).

## What is simulated

These are clearly labelled **SIMULATED** in the UI and do nothing outside WatchMe:

- Connector cards other than the live Splunk connector (no metrics, cannot be tested)
- Containment actions (isolate host, revoke sessions, block indicator)
- Ticket pushes to Jira, Slack and ServiceNow (recorded on the case only)
- Query console engines other than Splunk (sample rows)
- 1-hop expansion in demo mode

## Security notes

- No login yet. The server binds to `127.0.0.1` by default; put it behind an authenticating proxy before exposing it.
- Usernames are validated before being placed in SPL (letters, digits, `. _ @ $ - \`), so a search term cannot inject SPL.
- Set `WEBHOOK_SECRET` before accepting alerts from other systems; callers send it in `X-WatchMe-Secret`.
- Admin config updates accept only tags, VIPs, risk weights and retention, with validation.

## API (selected)

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/api/status` | Data source, storage, AI configuration |
| GET | `/api/graph/:user?windowDays=2&t0=ISO&refresh=1` | Build or return the user's graph |
| POST | `/api/graph/expand` | 1-hop expansion of a host/IP/domain (Splunk mode) |
| POST | `/api/cases` | Save the current graph as a case snapshot |
| POST | `/api/cases/:id/evidence` | Register an evidence file's SHA-256 |
| POST | `/api/gemini/case-summary` | Generate a summary (AI or deterministic) |
| POST | `/api/integrations/webhook` | Inbound alert (`entity`, `alertType`, `severity`, `source`, optional `timestamp`, `ttp`) |

## Scripts

| Command | What it does |
| --- | --- |
| `npm run dev` | API + Vite dev server with hot reload |
| `npm run build` then `npm start` | Production build served by the same server |
| `npm run lint` | Type-check |
| `npm run mock:splunk` | Mock Splunk REST API on port 8089 |
| `npm run mock:elastic` | Mock Elasticsearch search API on port 9200 |
