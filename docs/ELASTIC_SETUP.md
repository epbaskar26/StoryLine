# Live data with Elastic (free) on Windows

This sets up Elasticsearch and Kibana in Docker Desktop, ships your own laptop's Windows event logs into it with Winlogbeat, and points WatchMe at it. Everything is free (Elastic Basic license) and stays on localhost.

```
Windows event logs ──> Winlogbeat (Windows service) ──> Elasticsearch :9200 (Docker) ──> WatchMe :3000
                                                        └─> Kibana :5601 (optional, for browsing raw events)
```

Time needed: about 30 minutes. RAM: Elasticsearch and Kibana use about 2 to 3 GB.

Versions must match: Elasticsearch, Kibana and Winlogbeat are all 8.19.13 here. If you change `ELASTIC_VERSION`, download the same Winlogbeat version.

## 1. Set passwords in WatchMe's .env

In the WatchMe folder (for example `C:\Users\epbas\Downloads\watchme`), copy `.env.example` to `.env` if you have not already, and set:

```
DATA_SOURCE=elastic
ELASTIC_URL=http://localhost:9200
ELASTIC_USERNAME=elastic
ELASTIC_PASSWORD=changeme
KIBANA_PASSWORD=kibanachangeme
ELASTIC_INDEX=winlogbeat-*
DEFAULT_T0=
```

Docker Compose reads the same `.env` file, so the passwords you put here are the ones Elasticsearch is created with. Pick your own passwords if you like; you will need `ELASTIC_PASSWORD` again in step 3. Change them before the first start: once the data volume exists, the elastic password is fixed (see Troubleshooting to reset).

## 2. Start Elasticsearch and Kibana

Open PowerShell in the WatchMe folder:

```powershell
docker compose -f docker-compose.elastic.yml up -d
docker compose -f docker-compose.elastic.yml ps
```

The first start downloads about 1.5 GB of images. Wait until `elasticsearch` shows `healthy` and `kibana` shows `Up` (1 to 3 minutes). `kibana-setup` shows `Exited (0)`; that is expected.

Check:

```powershell
curl.exe -u elastic:changeme http://localhost:9200
```

You should see JSON with `"number" : "8.19.13"`. Kibana is at http://localhost:5601 (log in as `elastic` with your ELASTIC_PASSWORD).

## 3. Install Winlogbeat

1. Download the Winlogbeat 8.19.13 Windows zip:
   https://artifacts.elastic.co/downloads/beats/winlogbeat/winlogbeat-8.19.13-windows-x86_64.zip
2. Extract it and rename the folder to `C:\Program Files\Winlogbeat`.
3. Copy `tools\winlogbeat\winlogbeat.yml` from the WatchMe folder over `C:\Program Files\Winlogbeat\winlogbeat.yml`. If you changed ELASTIC_PASSWORD, edit the `password:` line.
4. Open PowerShell **as Administrator**:

```powershell
cd 'C:\Program Files\Winlogbeat'

# Check the config and the connection to Elasticsearch
.\winlogbeat.exe test config -c .\winlogbeat.yml -e
.\winlogbeat.exe test output -c .\winlogbeat.yml -e

# Load the index template, ingest pipelines and Kibana dashboards
.\winlogbeat.exe setup -e
.\winlogbeat.exe setup --pipelines -e

# Install and start the service
PowerShell.exe -ExecutionPolicy UnRestricted -File .\install-service-winlogbeat.ps1
Start-Service winlogbeat
Get-Service winlogbeat
```

The service runs as Local System, which is needed to read the Security log. It backfills the last 30 days of Security and Sysmon events (the history WatchMe uses as the baseline), so the first run can take a few minutes.

Check that data arrives:

```powershell
curl.exe -u elastic:changeme "http://localhost:9200/winlogbeat-*/_count"
```

The count should grow. Winlogbeat's own log is in `C:\ProgramData\winlogbeat\logs`.

## 4. Turn on extra Windows auditing (recommended)

By default Windows logs logons (4624/4625) and group changes (4732), but not process creation. In an Administrator PowerShell:

```powershell
auditpol /set /subcategory:"Process Creation" /success:enable
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f
```

This gives event 4688 with command lines, which WatchMe uses to detect encoded PowerShell.

## 5. Install Sysmon (optional, better data)

Sysmon adds process, network connection, file and DNS events (event IDs 1, 3, 11, 22). WatchMe uses them for C2 connections, domains and file activity.

1. Download Sysmon from https://learn.microsoft.com/sysinternals/downloads/sysmon and extract it.
2. Download a config, for example SwiftOnSecurity's `sysmonconfig-export.xml` from https://github.com/SwiftOnSecurity/sysmon-config
3. In an Administrator PowerShell in the Sysmon folder:

```powershell
.\sysmon64.exe -accepteula -i sysmonconfig-export.xml
Restart-Service winlogbeat
```

Winlogbeat already has the Sysmon channel in its config; it picks up the events after the restart.

## 6. Run WatchMe

```powershell
npm install
npm run dev
```

The header badge should read **ELASTIC (LIVE)**. Find your username:

```powershell
whoami
```

The part after the backslash is the name to search (for example `baskaranep\epbas` means `epbas`). If you sign in with a Microsoft account, the logon events may use a different name; type part of it into the WatchMe search box (Ctrl+K) and pick from the list, or open the URL directly:

http://127.0.0.1:3000/?entity=epbas

In **Integrations**, "Test connection" on the Elastic connector shows the Elasticsearch version and document count, and the query console accepts Lucene queries such as:

```
event.code:(4624 OR 4625) AND user.name:"epbas"
```

## 7. Generate safe test activity

These create real events on your own laptop without changing anything.

Brute force then success (6 failures, then a success, within 30 minutes). Run in a normal PowerShell or cmd window:

```powershell
runas /user:epbas cmd
```

Type a wrong password 6 times (run the command again each time), then run it once more with the correct password. Close the cmd window that opens. Replace `epbas` with your username; for a Microsoft account use `runas /user:MicrosoftAccount\you@example.com cmd`.

Encoded PowerShell (needs step 4 or Sysmon). This only prints "WatchMe test":

```powershell
powershell -enc VwByAGkAdABlAC0ASABvAHMAdAAgACIAVwBhAHQAYwBoAE0AZQAgAHQAZQBzAHQAIgA=
```

Wait about a minute for Winlogbeat to ship the events, then reload the investigation. You should see "Brute force then success" and "Encoded PowerShell" in the risk factors and on the Attack Path.

Your laptop alone will not trigger lateral movement or new-source-IP indicators; those need logons to other machines. Use `npm run mock:elastic` (below) to see every indicator.

## Testing without Docker

`npm run mock:elastic` starts a mock of the Elasticsearch search API on port 9200 with a planted attack story for user `epbas` on host `baskaranep`, relative to the current time. Stop the Docker stack first (both use port 9200), then use:

```
DATA_SOURCE=elastic
ELASTIC_URL=http://127.0.0.1:9200
ELASTIC_USERNAME=elastic
ELASTIC_PASSWORD=changeme
```

## Stopping and cleaning up

```powershell
docker compose -f docker-compose.elastic.yml stop        # stop, keep data
docker compose -f docker-compose.elastic.yml down -v     # remove containers and all indexed data
Stop-Service winlogbeat                                  # stop shipping logs
```

To remove Winlogbeat: in an Administrator PowerShell in `C:\Program Files\Winlogbeat`, run `PowerShell.exe -ExecutionPolicy UnRestricted -File .\uninstall-service-winlogbeat.ps1`, then delete the folder.

## Troubleshooting

| Symptom | Fix |
| --- | --- |
| `elasticsearch` keeps restarting; logs mention `vm.max_map_count` | Run `wsl -d docker-desktop sysctl -w vm.max_map_count=262144`, then `docker compose -f docker-compose.elastic.yml up -d`. This resets when Docker Desktop restarts. |
| `elasticsearch` exits with code 137 | Out of memory. Give Docker more memory (Docker Desktop > Settings > Resources, or `.wslconfig` for WSL 2) or close other apps. |
| `test output` fails with 401 | The password in `winlogbeat.yml` does not match ELASTIC_PASSWORD. |
| Changed ELASTIC_PASSWORD but login still uses the old one | The password is set when the data volume is first created. Run `down -v` (deletes data) and `up -d` again. |
| `setup` fails with a version error | Winlogbeat and Elasticsearch versions differ. Use the same version for both. |
| Kibana says "Kibana server is not ready yet" | Wait a minute. If it persists, check `docker compose -f docker-compose.elastic.yml logs kibana-setup`. |
| `_count` stays at 0 | Check `Get-Service winlogbeat` and the log in `C:\ProgramData\winlogbeat\logs`. The service must run as Administrator/Local System to read the Security log. |
| WatchMe says the user has no events | Check the exact name in Kibana (Discover, index `winlogbeat-*`, field `user.name`) and that the events are inside the last 48 hours. Leave `DEFAULT_T0` empty for live data. |
| No 4688 or encoded PowerShell events | Do step 4, or install Sysmon (step 5). |
| Port 9200 already in use | The mock (`npm run mock:elastic`) or another Elasticsearch is running. Stop it. |

## Security notes

- Ports 9200 and 5601 are bound to 127.0.0.1, so only your laptop can reach them. Keep it that way; the setup uses HTTP, not TLS.
- Your Security log contains real account names and IP addresses. The AI summary only sends tokenized data (USER_1, HOST_1...), but saved cases in WatchMe hold the real names.
- `changeme` is a lab default. Use your own passwords if the laptop is shared.
