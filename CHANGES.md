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
