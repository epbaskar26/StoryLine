# Generating test activity for WatchMe (lab VM)

Benign commands that produce the real Windows events WatchMe reads. Run them **in the isolated lab VM, in an Administrator PowerShell**. None of these are malware, and none read credentials or delete your data. Revert the `clean-baseline` snapshot when finished.

The easiest way is the bundled script:

```powershell
# in the VM, elevated
cd <folder with the script>
.\Test-WatchMeActivity.ps1 -All
# or a subset:
.\Test-WatchMeActivity.ps1 -Test service,scheduledtask,runkey,lsass,defender
# undo:
.\Test-WatchMeActivity.ps1 -Cleanup
```

Then in WatchMe (on the PC): open the VM user, or press Ctrl+K, type `host.name:"<VM-NAME>"` and pick **Graph log search**, and turn on **Live**. Allow about a minute for Winlogbeat to ship the events.

Prerequisites: Sysmon installed, PowerShell script-block logging on, and the updated `winlogbeat.yml` (which ships the Security, System, Application, Sysmon, TaskScheduler and Defender logs). The script turns on the audit policy that 4698 / 4740 / 4672 need.

## The individual commands

Run each in an elevated PowerShell if you prefer not to use the script.

**Software install / uninstall** → Application log 11707 / 11724 → `software` node
```powershell
# synthetic, offline-safe:
Write-EventLog -LogName Application -Source MsiInstaller -EventId 11707 -EntryType Information -Message 'Product: WatchMe Test App -- Installation completed successfully.'
Write-EventLog -LogName Application -Source MsiInstaller -EventId 11724 -EntryType Information -Message 'Product: WatchMe Test App -- Removal completed successfully.'
# with a real installer instead: msiexec /i C:\path\app.msi /qn   then   msiexec /x C:\path\app.msi /qn
```

**Service install** → System log 7045 → `service` node, "Service installed"
```powershell
sc.exe create WatchMeTestSvc binPath= "C:\Windows\System32\cmd.exe /c echo test" start= demand
sc.exe delete WatchMeTestSvc   # cleanup
```

**Scheduled task** → TaskScheduler 106 / Security 4698 → `task` node
```powershell
schtasks /create /tn WatchMeTestTask /tr C:\Windows\System32\notepad.exe /sc once /st 23:59 /f
schtasks /delete /tn WatchMeTestTask /f   # cleanup
```

**Registry autorun / Run key** → Sysmon 13 → `registry` node, "Registry autorun persistence"
```powershell
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v WatchMeTest /t REG_SZ /d "C:\Windows\System32\calc.exe" /f
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v WatchMeTest /f   # cleanup
```

**LSASS access** → Sysmon 10 → "LSASS process access" (T1003.001)
```powershell
# lists LSASS's loaded DLLs; it does NOT read credentials or memory secrets
tasklist /m /fi "IMAGENAME eq lsass.exe"
```

**Microsoft Defender detection** → Defender 1116 → `DETECTED`, "Security product detection"
```powershell
# EICAR is the industry-standard harmless antivirus test file
$e = 'X5O!P%@AP[4\PZX54(P^)7CC)7}' + '$' + 'EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
New-Item -ItemType Directory -Force C:\WatchMeTest | Out-Null
Set-Content C:\WatchMeTest\eicar.com -Value $e -Encoding Ascii -NoNewline   # Defender removes it = the detection
```

**Account lockout** → Security 4740 → "Repeated account lockouts"
```powershell
net accounts /lockoutthreshold:3
New-LocalUser watchmelab -Password (ConvertTo-SecureString 'C0rrect-Horse!' -AsPlainText -Force)
Add-Type -Namespace W -Name N -MemberDefinition '[DllImport("advapi32.dll")] public static extern bool LogonUser(string u,string d,string p,int a,int b,out System.IntPtr t);'
$t=[IntPtr]::Zero; 1..4 | % { [W.N]::LogonUser('watchmelab',$env:COMPUTERNAME,'WRONG',2,0,[ref]$t) | Out-Null }
Remove-LocalUser watchmelab; net accounts /lockoutthreshold:0   # cleanup
```

**Special privileges** → Security 4672 → shown as privilege activity
```powershell
# any elevated logon emits 4672; the service/task steps above already did. To force one:
Start-Process powershell -Verb RunAs -ArgumentList '-Command','whoami /priv'
```

**Audit log cleared** → System 104 → "Audit log cleared" (T1070.001)
```powershell
# clears a low-value log, not the Security log; the snapshot restores it
wevtutil cl "Windows PowerShell"
```

**USB device** → shown as generic activity (no dedicated node yet)
- In VirtualBox: **Devices > USB >** pick a device. It appears on the host as a generic event, in the Event Timeline and the coverage count. Ask me to add a dedicated USB node if you want one.

**Cloud sign-ins (M365 / Entra / AWS / Okta)** → cannot be generated on the VM
These come from cloud audit logs, not the endpoint. For a lab test, index synthetic docs into Elasticsearch **from the PC**:
```bash
bash tools/lab/inject-cloud-events.sh            # defaults: localhost:9200, elastic:changeme, user epbas
```
Then add the test index in `.env` and restart WatchMe:
```
ELASTIC_INDEX=winlogbeat-*,cloud-signins-test
```
Open the user and the cloud services appear as sign-in steps. Remove with `curl -u elastic:changeme -X DELETE http://localhost:9200/cloud-signins-test`.

## What to expect in WatchMe

After ~1 minute, the Attack Path / graph shows a node per activity, the risk panel lists the matching indicators (Service installed, Scheduled task created, Registry autorun persistence, LSASS process access, Security product detection, Software installed, Audit log cleared, Repeated account lockouts), and the top bar's **Event coverage** note counts each category. Anything unmapped (USB, misc.) shows as generic activity and is counted separately, never dropped.

## Cleanup

`.\Test-WatchMeActivity.ps1 -Cleanup` removes the test service, task, run key, folder and account and resets the lockout policy. Reverting the `clean-baseline` snapshot undoes everything, including the cleared log.
