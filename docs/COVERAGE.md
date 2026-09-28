# What WatchMe collects and graphs

WatchMe never drops an event: anything it doesn't model as its own step is shown as generic activity on the host it happened on, and counted in the "Event coverage" and "N events not modelled" data notes. The table below shows what has a dedicated node and risk rule today.

## Modelled with a dedicated node / edge / risk rule

| Activity | Windows source | Event IDs | Node / edge | Risk rule |
| --- | --- | --- | --- | --- |
| Logon success / failure | Security | 4624 4625 4648 4768 4769 4771 4776 | host, AUTH_SUCCESS / AUTH_FAIL | Brute force, lateral fan-out, new IP |
| Process creation | Sysmon 1 / Security 4688 | 1 / 4688 | process, EXECUTED / SPAWNED | Encoded PowerShell, command insight |
| PowerShell script block | PowerShell/Operational | 4104 | attached to the process | Encoded PowerShell |
| Network / DNS | Sysmon | 3 / 22 | ip, domain, CONNECTED_TO | Large upload, C2 |
| File create / access | Sysmon 11/23/26, Security 4663/5145 | — | file, WROTE / ACCESSED | Mass file access |
| Group / privilege change | Security | 4728 4732 4756 4720 4738 | user (group), MEMBER_CHANGE | Privilege change |
| Software install / uninstall | Application (MsiInstaller) | 11707 11724 1033 1034 | software, INSTALLED / UNINSTALLED | Software installed |
| Service install | System 7045 / Security 4697 | 7045 4697 | service, SERVICE_INSTALL | Service installed |
| Scheduled task | TaskScheduler / Security | 106 4698 | task, SCHEDULED_TASK | Scheduled task created |
| Registry autorun | Sysmon | 12 13 14 | registry, REGISTRY_SET | Registry autorun persistence |
| LSASS / process access | Sysmon | 10 | ACCESSED_PROCESS | LSASS process access |
| Defender / EDR detection | Defender/Operational | 1116 1117 1006 1007 | alert, DETECTED | Security product detection |
| Account lockout | Security | 4740 | on the host | Repeated account lockouts |
| Audit log cleared | Security / System | 1102 104 | on the host | Audit log cleared |
| Cloud sign-in | M365 / Entra / AWS / Okta | (add-on) | domain, AUTH_SUCCESS | (as auth) |
| SIEM / webhook alert | any | — | alert, TRIGGERED | Correlated alert |

## Shown as generic activity (not yet a dedicated node)

Everything else Winlogbeat or Splunk sends: driver/DLL loads (Sysmon 6/7), pipe events (17/18), WMI (19–21), USB device connects, logoff/RDP reconnect, and any provider WatchMe doesn't recognise. These appear on the host as an `OBSERVED` edge and in the Event Timeline, and are counted in the data notes. Ask to promote any of them to a dedicated node.

## Not collected until you enable it

- **Process creation (4688) with command line:** `auditpol` + the registry flag (ELASTIC_SETUP.md step 4). Sysmon 1 is the better source.
- **PowerShell script text (4104):** the ScriptBlockLogging registry key (ELASTIC_SETUP.md step 4).
- **Registry, LSASS access, network:** need **Sysmon** (ELASTIC_SETUP.md step 5).
- **Service installs in the Security log (4697):** need "Audit Security System Extension" enabled; 7045 in the System log needs nothing.

The updated `tools/winlogbeat/winlogbeat.yml` already collects the Security, System, Application, Sysmon, PowerShell, TaskScheduler and Defender logs. Replace your existing file with it and run `Restart-Service winlogbeat`.

## Splunk

Point `SPLUNK_INDEX` at an index that receives the Windows Security, System and Application logs (the Splunk Add-on for Microsoft Windows collects all three). WatchMe reads the same event IDs. Sysmon needs the Splunk Add-on for Sysmon. No WatchMe change is needed; it queries these on demand.
