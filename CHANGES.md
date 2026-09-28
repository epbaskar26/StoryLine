# Changes in 0.7.5

- **Fix: on a busy real workstation the event budget filled with OS/UI noise, so older activity was trimmed and 2-day vs 7-day looked the same.** WatchMe now drops high-volume benign process noise at query time (conhost, RuntimeBroker, msedgewebview2, backgroundTaskHost, search/telemetry helpers, etc.), so the cap and the graph focus on meaningful activity and the window covers its full span. Attacker-relevant binaries (svchost, rundll32, powershell, cmd, wscript, mshta, sc, schtasks...) are always kept. Toggle with `ELASTIC_DENOISE=false`; add your own names with `ELASTIC_EXCLUDE_PROCS=docker.exe,node.exe`.
- The Elastic event cap default is raised to 50,000 (from 20,000).
- **Fix: the Live button could spin without updating.** Live now skips a refresh if the previous one is still running, so slow queries no longer leave it stuck.

# Changes in 0.7.4

- **Fix: a wide window showed fewer events than a narrow one, and recent activity (e.g. the encoded PowerShell you just ran) was missing.** The Elastic reader fetched events oldest-first and capped at ELASTIC_MAX_EVENTS, so a busy 7-day window kept the oldest 20,000 and dropped the newest. It now fetches newest-first, so the most recent events are always kept (the "returned the maximum" note still tells you when older activity was trimmed).

# Changes in 0.7.3

- **Fix: recent events did not appear; Re-query and Edit window seemed frozen.** The window used to pin its end time at the first load, so activity that arrived afterwards fell outside it and Re-query kept rebuilding the same past window. Now the window ends at "now" by default and stays static only until you act: **Re-query** refetches up to the current moment (new events appear), **Live** follows every 30 s, and **Edit window** with a custom start/end sets a FIXED historical window. The badge shows STATIC (ends now), LIVE, or FIXED.
- **Seeder writes into your existing Elasticsearch by default.** `node tools/lab/seed-elastic.mjs` now detects the Winlogbeat data stream and indexes the fictional logs into it (tagged `labels.seeded=watchme-demo`), so real (epbas) and fictional (jsmith, aturner) identities are queryable from the same URL with no `.env` change. `--index <name>` forces a separate index instead; `--cleanup` removes everything the seeder added; `--reset` re-seeds.

# Changes in 0.7.2

- **Dummy log seeder** `tools/lab/seed-elastic.mjs` (`npm run seed:elastic`): bulk-loads ~54 realistic Winlogbeat/ECS documents into your real Elasticsearch, timestamped relative to now, covering a full kill chain plus install, service, scheduled task, registry, LSASS, Defender, lockout, audit-clear and cloud sign-in events, across two users and several hosts. WatchMe and Kibana both read them. `--reset`, `--dry`, `--index` supported.
- **Fix:** the Elastic normalizer did not attach the account to install / uninstall / Defender / generic events, so they were missing from a user's graph (they only appeared in a host search). These now carry their user, so "Software installed", "Security product detection" and "Audit log cleared" fire in a normal user investigation. The same fallback was added to the Splunk normalizer.

# Changes in 0.7.0

## Full activity coverage

- **Nothing is dropped.** Any event WatchMe does not model as its own step now appears as generic activity (an `OBSERVED` edge) on the host it happened on, is listed in the Event Timeline, and is counted in two new data notes: **Event coverage** (a per-category breakdown) and **N events not modelled yet**. You see everything on day one; the unmapped list shows what to promote next.
- **New event types, each with a node, edge and risk rule:**
  - Software install / uninstall (MsiInstaller 11707/11724/1033/1034) → `software` node, "Software installed".
  - Windows service install (System 7045, Security 4697) → `service` node, "Service installed" (T1543.003).
  - Scheduled task creation (106 / 4698) → `task` node, "Scheduled task created" (T1053.005).
  - Registry autorun (Sysmon 12/13/14) → `registry` node, "Registry autorun persistence" (T1547).
  - LSASS / process access (Sysmon 10) → `ACCESSED_PROCESS` edge, "LSASS process access" (T1003.001).
  - Microsoft Defender / EDR detections (1116/1117) → `DETECTED` edge, "Security product detection".
  - Account lockouts (4740), audit-log-cleared (1102/104, "Audit log cleared", T1070.001), special privileges (4672), USB devices, and cloud sign-ins (M365 / Entra / AWS / Okta).
- **Host events in user investigations.** When you open a user, WatchMe also pulls host-only events (service, task, Defender, registry, log-clear) from the hosts that user logged onto, so activity with no user field still shows up. Toggle with `INCLUDE_HOST_EVENTS`.
- **Collection updated.** `tools/winlogbeat/winlogbeat.yml` now ships the System, Application, TaskScheduler and Defender logs as well. New `docs/COVERAGE.md` lists every mapped event ID and what still needs Sysmon or auditing turned on. Replace your Winlogbeat config and `Restart-Service winlogbeat`.
- New icons and graph shapes for software, service, task, registry, device and generic-event nodes.
- The Marcus Ross demo now includes a Defender detection, an LSASS access, a persistence service and a remote-access-tool install.

# Changes in 0.6.0

## New

- **AI Storyline** (new investigation tab): groups the Attack Path into attack phases (Initial Access, Execution, Persistence ...) with a plain-language explanation per step, laid out as a flow chart. The AI only interprets: it receives the evidence steps (names tokenized, command text quoted as untrusted data), must cite step ids, and anything citing a step that is not in the evidence is dropped and counted. Log text that looks like an instruction to the model is flagged as possible prompt injection. Without an AI provider a rule-based storyline is built from the indicators. **Approve & save to case** freezes the storyline (with its SHA-256) into the case.
- **Ollama** as a local AI provider (`AI_PROVIDER=ollama`, `OLLAMA_URL`, `OLLAMA_MODEL`), for the storyline and the case summary. Gemini still works as before.
- **Assign & Close**: assign an investigation, set status, and close it with a disposition (true positive malicious / authorized, false positive, inconclusive, duplicate) and closure notes. A case with the graph snapshot is created if needed. Reopen is supported.
- **Notes** tab: every hypothesis, verdict, assignment, closure and approved storyline is recorded as an append-only note (and in the audit log). Manual notes can be added.
- **Graphs from manual searches**: "Build graph from results" in the Integrations query console, "Graph log search" in Ctrl+K, and "Graph all activity on this host/IP/domain" in the entity panel. Search graphs show every matched identity; risk is scored per identity.
- **Live mode**: the window ends at "now" and re-queries every 30 s; new entities are tagged NEW.
- **Command insight**: process nodes keep every distinct command line (full text, up to 32 KB). Encoded PowerShell is decoded, and known techniques are flagged (download cradles, credential dumping, shadow-copy deletion, masquerading double extensions, rundll32 from user folders ...). The Attack Path shows a one-line command summary under each process step and a hover popover with the details.
- PowerShell script block logging (event 4104) is read from Elastic and attached to the PowerShell process.

## Fixed

- Times are shown as real local times (with the zone, UTC on hover) everywhere instead of T-20 / T-40 offsets: scrubber, Attack Path cards, revisit notes, timeline, entity panel, replay overlay, case summary.
- The window no longer slides: after the first load the end time is frozen, so nodes do not drop out as time passes. **Edit window** sets any start and end (up to 7 days) and re-queries; **Re-query** refreshes the same window.
- Mark benign / Mark malicious now opens a reason box with **Save verdict**; verdicts are saved as notes, shown on the entity and on its Attack Path card.
- Hypotheses (entity panel) are saved to the notes; the panel lists all notes about that entity.
- Telemetry attributes show full values (no truncation), can be selected, and each value (or all of them) can be copied.
- The graph continues past an executable: child processes (SPAWNED), files written (WROTE) and connections are attributed to the process that made them (Sysmon 1/3/11/22). The Marcus Ross demo now shows Outlook → dropper → rundll32 beacon → PowerShell → persistence → share discovery → shadow-copy deletion → ransomware canary.
- Follow (Attack Path) now scrolls both ways to the newest step and pulses it, shows "Following" while active, and turns back on after panning.
- Icons show what an entity is (mail client, browser, shell, server, archive, cloud storage ...) instead of generic emoji. Vendor logos are not used (trademarks; fetching favicons for investigated domains would also leak the investigation).

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
