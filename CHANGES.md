# Changes in 0.5.0

- New live data source: **Elasticsearch** (free Basic license). Set `DATA_SOURCE=elastic` and `ELASTIC_URL`. Reads Winlogbeat / ECS data: Windows Security logons, failures, process creation, group changes and file access; Sysmon process, network, file and DNS events; proxy-style web events. Falls back to raw `winlog.event_data.*` fields when Winlogbeat's ingest pipelines are not loaded.
- `docker-compose.elastic.yml`: Elasticsearch and Kibana 8.19.13, single node, bound to localhost, passwords from `.env`.
- `tools/winlogbeat/winlogbeat.yml` and `docs/ELASTIC_SETUP.md`: step-by-step Windows guide to ship your own laptop's event logs, with safe test activity (failed `runas` logons, harmless encoded PowerShell).
- Data sources now sit behind one `LogSource` interface (`server/sources.ts`), so Splunk and Elastic share the same graph builder, risk scoring, baseline, 1-hop expansion, user search, query console and connection test.
- Integrations: the live connector shows the configured source; the query console uses Lucene syntax for Elastic. Header badge shows **ELASTIC (LIVE)**.
- `npm run mock:elastic`: a mock of the Elasticsearch search API with a planted attack for user `epbas`, relative to the current time.

# Changes in 0.4.0

- New default view: **Attack Path**, a linear, time-ordered view of the investigation. It starts at the user and the first login, then shows each step (entity reached) left to right, wrapping into rows like text. The cluster view is still available as **Relationship Graph**.
- **Revisits:** when the path returns to an entity it already reached, the step is drawn as a normal node with a `↺ REVISIT ×n` tag and a note such as "Back after 14h · first seen T-46:00".
- Routine steps (low-risk, seen before) are collapsed into "+N routine" chips; click a chip or tick "Show routine steps" to expand them.
- Each step shows its ATT&CK tactic and technique, event count, and time (offset and UTC). A dashed connector means the entity was first seen (not in the baseline).
- Risk is now tracked per visit: the backend splits each edge into visits (a new visit after 30 minutes without activity) and colours each visit only by the indicator events inside it, so a normal login is not shown as critical because a later login on the same host was.
- The time scrubber and replay recording work in the Attack Path view (the path grows step by step and the view follows the newest step).

# Changes in 0.3.0

- New light theme based on the reference design: Inter font; royal blue #2740CB primary and #3140CB links; #F6F8FA page, white cards, #EDEFF1 borders; risk colors orange #FBA21B, red #D75054, teal #13A8B1, purple #843CF3. It is the default. The moon/sun button switches to the original dark theme, and the choice is remembered.
- Flat styling: neon glows removed, the graph canvas uses the new palette, nav labels no longer wrap, and the Download button is primary blue.
- Code, queries and hashes stay monospace (JetBrains Mono).

# Changes in 0.2.0

## Broken features fixed

- `/api/users` did not exist, so the user picker and Ctrl+K search were always empty. Added.
- The event timeline table was never rendered, and "Events Log" in the node drawer did nothing. The Investigation view now has Graph / Event Timeline tabs; Events Log filters the table to the selected node.
- "Generate Replay" switched to the Replay tab before recording, which unmounted the graph canvas, so recordings captured nothing. Recording now runs on the graph view and switches tabs when done.
- The force-directed graph diverged to NaN about 1 second after loading (the spring force grew with distance squared), which threw inside the render loop and froze the canvas. The spring is now linear and capped, velocities are capped, and non-finite positions are recovered.
- `npm install` failed: the esbuild version conflicted with Vite 8's peer range. Bumped to ^0.28.0.
- Unknown users silently showed J.Smith's graph (fallbacks everywhere). They now return a 404 with a clear message.
- Watchlist had no way to add an entity from the UI. Search results now have a "+ Watch" button.
- Annotations showed "Saved to Case!" but were not saved. They are now stored (and appear in case snapshots).
- "Save Tags" in Admin had nothing to edit, and the audit log was fetched but never shown. Tags, VIP identities and risk weights are editable; the audit log is displayed and filterable.
- "Resume Investigation Canvas" only switched tabs. Cases now store a graph snapshot and reopen it.
- Push to ticket always updated the most recent case. It now uses the case for the current investigation.

## Privacy boundary (AI summary)

- Tokenization matched names while edges referenced ids, so every fact became `ENTITY_SRC ... ENTITY_TGT`. Tokens are now keyed by node id (USER_1, HOST_2 ...).
- Contributing-factor descriptions sent raw IPs and hostnames to the model. Free text is now scrubbed (entity names and name fragments, IPs, emails, DOMAIN\user, file paths).
- Node ids were readable (`u_jsmith`) and leaked names through citations. Ids are now opaque hashes.
- The fallback summary was hardcoded to J.Smith's story (with "98% confidence") for every user. It is now generated from the actual graph.
- "100% Citations Verified" was hardcoded. Citations are now checked against real node/edge ids, and uncited lines are counted.
- The Privacy Inspector showed a static example; it now shows the exact payload sent.
- Analyst approval is recorded in the audit log with the summary's SHA-256.

## Honest UI

- Replay: the SHA-256 was a fixed string and the overlay said "SHA-256 VERIFIED". The hash is now computed over the actual file; the overlay claim is removed.
- Replay files were WebM but downloaded as `.mp4`/`.gif`. The format is detected (MP4 in Chrome/Edge, WebM elsewhere) and the extension matches. GIF is not offered.
- Duration, redaction and title controls did nothing. They now change the recording. Resolution is shown as the real canvas size.
- Histogram bars were hardcoded to J.Smith's pattern. They are computed from the graph's edges.
- "Time-to-Context 32s (was 45m)" was fixed text. The banner shows the measured graph load time.
- The 7-day button did not change the scrubber (fixed at 48). Scrubber, replay and labels follow the window.
- Connector EPS/latency figures were random numbers; containment and ticket pushes reported success without doing anything. All are labelled SIMULATED, and the audit log records them as simulated.
- Removed claims about Kafka and Memgraph, which are not part of this build.

## New: real data path

- Splunk adapter (`server/splunk.ts`): SPL over the REST export endpoint, baseline query, user search, 1-hop expansion, ad-hoc SPL console, connection test. Entity values are validated before use in SPL.
- Normalizer (`server/normalize.ts`): Windows Security (4624/4625/4648/4688/4728/4663...), Sysmon (1/3/11/22), web proxy and generic CIM fields.
- Graph builder and risk engine (`server/graphBuilder.ts`, `server/risk.ts`): real timestamps, baseline comparison, and nine explainable indicators; the graph is capped and truncation is reported.
- Storage (`server/store.ts`): PostgreSQL when `DATABASE_URL` is set (append-only audit log enforced by a trigger), otherwise in memory.
- Alert webhook with optional shared secret; alerts are stored and attached to the entity's graph.
- Admin config updates are validated (no arbitrary JSON merge). The server binds to 127.0.0.1 by default.
- `tools/mock-splunk.mjs` for testing without Splunk; `docker-compose.yml` for Splunk Free + PostgreSQL.
