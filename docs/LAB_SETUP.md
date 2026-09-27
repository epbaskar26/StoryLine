# Isolated VirtualBox lab for WatchMe

A Windows VM sends its event logs to Elasticsearch on your PC over a private VirtualBox network. The VM has no internet and no access to your home network. WatchMe runs on the PC, as now.

```
Your PC (host)                                   Lab VM (VirtualBox)
Docker Desktop: Elasticsearch :9200  <────────── Winlogbeat + Sysmon
WatchMe :3000                        host-only    no NAT, no bridged adapter
                                     192.168.56.x
```

Rules for this lab:

- The VM has **only** a host-only adapter. Never add NAT or Bridged while testing.
- Shared clipboard, drag and drop, and shared folders are **off**.
- Revert to the clean snapshot after every test.
- Use a lab-only Windows account and no real credentials inside the VM.
- If the PC or accounts belong to your employer, get written approval before any security testing.

## 1. Host-only network

1. VirtualBox > File > Tools > Network Manager > Host-only Networks.
2. If there is none, click **Create**. Note its IPv4 address, usually `192.168.56.1`, and turn the DHCP server on.
3. On the PC, check with `ipconfig`: look for "VirtualBox Host-Only Network" with that address.

If your address is different, replace `192.168.56.1` everywhere below.

## 2. Create the lab VM

1. Windows 10/11 VM (Microsoft offers evaluation ISOs), 2 CPUs, 4 GB RAM, 60 GB disk.
2. Install Windows with a local account, then install the VirtualBox Guest Additions.
3. Settings > Network: Adapter 1 = **Host-only Adapter** (the network above). Adapters 2-4 disabled.
4. Settings > General > Advanced: Shared Clipboard **Disabled**, Drag'n'Drop **Disabled**.
5. Settings > Shared Folders: none.
6. Inside the VM, `ping 192.168.56.1` should work and `ping 8.8.8.8` should fail.

To copy the Winlogbeat and Sysmon installers in, temporarily attach them as an ISO (e.g. build one with any ISO tool) or download them before switching the adapter to host-only. Do not leave NAT enabled.

## 3. Let Elasticsearch accept the VM

In WatchMe's `.env` on the PC add:

```
ELASTIC_BIND=192.168.56.1
```

Then restart the stack:

```powershell
docker compose -f docker-compose.elastic.yml up -d
curl.exe -u elastic:changeme http://192.168.56.1:9200
```

Elasticsearch now listens on the host-only address only (not on your Wi-Fi). Kibana stays on 127.0.0.1. WatchMe keeps using `ELASTIC_URL=http://localhost:9200`; Docker publishes the port on the host-only address, so if `localhost` stops working set `ELASTIC_URL=http://192.168.56.1:9200` in `.env` too.

Windows Firewall may ask to allow Docker on the host-only network: allow **Private** only.

Use a stronger `ELASTIC_PASSWORD` than `changeme` now that another machine can reach it (see ELASTIC_SETUP.md, "Changed ELASTIC_PASSWORD").

## 4. Winlogbeat and Sysmon in the VM

1. Install Sysmon with a standard configuration (ELASTIC_SETUP.md, step 5).
2. Enable process-creation auditing and PowerShell script block logging (ELASTIC_SETUP.md, step 4).
3. Install Winlogbeat 8.19.13 to `C:\Program Files\Winlogbeat` and copy `tools\winlogbeat\winlogbeat-lab-vm.yml` over its `winlogbeat.yml` (set the password). It sends to `192.168.56.1:9200`.
4. In an Administrator PowerShell in the VM:

```powershell
cd 'C:\Program Files\Winlogbeat'
.\winlogbeat.exe test output -e
PowerShell.exe -ExecutionPolicy UnRestricted -File .\install-service-winlogbeat.ps1
Start-Service winlogbeat
```

The index template and pipelines were already loaded from the PC, so `setup` is not needed in the VM.

## 5. Snapshot

Shut the VM down cleanly and take a snapshot named **clean-baseline**. Every test starts from it: Machine > Snapshots > Restore.

## 6. Check it end to end

In the VM, run the harmless test events from ELASTIC_SETUP.md step 7 (wrong-password `runas`, then the encoded `Write-Host`). In WatchMe on the PC:

- the VM's host name appears as a host node;
- open the VM user (Ctrl+K, type the user name) or graph the host: Ctrl+K `host.name:"<vm-name>"` then "Graph log search";
- the Attack Path shows the failed logons, the logon, and the PowerShell step with its decoded command;
- switch on **Live** in the window bar to watch new activity arrive every 30 s.

Restore **clean-baseline** afterwards.

## Troubleshooting

| Symptom | Fix |
| --- | --- |
| `test output` fails in the VM | Ping 192.168.56.1 from the VM; check `ELASTIC_BIND` and that Docker was restarted; allow Docker on Private networks in Windows Firewall. |
| Nothing arrives in WatchMe | `Get-Service winlogbeat` in the VM; count on the PC: `curl.exe -u elastic:<pw> "http://192.168.56.1:9200/winlogbeat-*/_count"`. |
| WatchMe cannot reach Elastic after the change | Set `ELASTIC_URL=http://192.168.56.1:9200` in `.env` and restart `npm run dev`. |
| VM times look wrong | Set the VM's time zone and enable time sync; WatchMe shows times in the PC browser's time zone. |
