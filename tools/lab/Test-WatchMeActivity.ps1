<#
  Test-WatchMeActivity.ps1  -  generate benign test events for WatchMe (LAB VM ONLY)

  Run in the isolated VirtualBox lab VM, in an ADMIN PowerShell. Every action is harmless
  and is undone by -Cleanup (and by reverting the clean-baseline snapshot). Nothing here
  dumps credentials, deletes data, or reaches the network.

  Usage:
    .\Test-WatchMeActivity.ps1 -All
    .\Test-WatchMeActivity.ps1 -Test service,scheduledtask,runkey
    .\Test-WatchMeActivity.ps1 -Cleanup

  Then in WatchMe: open the VM user, or Ctrl+K -> host.name:"<VM-NAME>" -> Graph log search,
  and turn on Live. Allow ~1 minute for Winlogbeat to ship the events.

  Requires (see docs/COVERAGE.md and ELASTIC_SETUP.md): Sysmon installed, PowerShell script-block
  logging on, and Winlogbeat shipping the Security, System, Application, Sysmon, TaskScheduler and
  Defender logs. Some events (4698, 4740, 4672) also need the audit policy lines below.
#>
[CmdletBinding()]
param(
  [switch]$All,
  [ValidateSet('software','service','scheduledtask','runkey','lsass','defender','lockout','privilege','auditclear','usb','cloud')]
  [string[]]$Test,
  [switch]$Cleanup
)

$ErrorActionPreference = 'Continue'
$TAG = 'WatchMeTest'
function Note($m){ Write-Host "[*] $m" -ForegroundColor Cyan }
function Ok($m){ Write-Host "[+] $m" -ForegroundColor Green }
function Warn($m){ Write-Host "[!] $m" -ForegroundColor Yellow }

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole('Administrators')) {
  Warn 'Run this in an ADMIN PowerShell. Some events will not be generated otherwise.'
}

# ---- one-time audit policy so 4698 / 4740 / 4672 are logged (safe to run repeatedly) ----
function Enable-Audit {
  Note 'Enabling audit policy for scheduled tasks, lockouts and privilege use'
  auditpol /set /subcategory:"Other Object Access Events" /success:enable | Out-Null   # 4698 scheduled task
  auditpol /set /subcategory:"Account Lockout" /failure:enable | Out-Null              # 4740
  auditpol /set /subcategory:"Special Logon" /success:enable | Out-Null               # 4672
  net accounts /lockoutthreshold:3 /lockoutduration:5 /lockoutwindow:5 | Out-Null      # lockout after 3 fails
}

# 1) Software install / uninstall  -> Application log, MsiInstaller 11707 / 11724 -> WatchMe "software" node
function Test-Software {
  Note 'Software install/uninstall (synthetic MsiInstaller events, offline-safe)'
  if (-not [System.Diagnostics.EventLog]::SourceExists('MsiInstaller')) {
    # MsiInstaller normally exists; only create a stand-in if missing
    New-EventLog -LogName Application -Source 'MsiInstaller' -ErrorAction SilentlyContinue
  }
  Write-EventLog -LogName Application -Source 'MsiInstaller' -EventId 11707 -EntryType Information `
    -Message 'Product: WatchMe Test App -- Installation completed successfully.'
  Start-Sleep -Milliseconds 500
  Write-EventLog -LogName Application -Source 'MsiInstaller' -EventId 11724 -EntryType Information `
    -Message 'Product: WatchMe Test App -- Removal completed successfully.'
  Ok 'Wrote install (11707) and uninstall (11724). If you have a real .msi, "msiexec /i x.msi /qn" and "/x" also work.'
}

# 2) Service install  -> System log 7045 -> WatchMe "service" node + "Service installed"
function Test-Service {
  Note 'Service install (harmless service pointing at cmd, then removed)'
  sc.exe create WatchMeTestSvc binPath= "C:\Windows\System32\cmd.exe /c echo WatchMe test" start= demand DisplayName= "WatchMe Test Service" | Out-Null
  Ok 'Created service WatchMeTestSvc (event 7045). It never runs; -Cleanup deletes it.'
}

# 3) Scheduled task  -> TaskScheduler 106 (+ Security 4698) -> WatchMe "task" node
function Test-ScheduledTask {
  Note 'Scheduled task creation (runs notepad; not enabled to fire)'
  schtasks /create /tn 'WatchMeTestTask' /tr 'C:\Windows\System32\notepad.exe' /sc once /st 23:59 /f | Out-Null
  Ok 'Created scheduled task WatchMeTestTask (event 106 / 4698).'
}

# 4) Registry autorun / Run key  -> Sysmon 13 -> WatchMe "registry" node + "Registry autorun persistence"
function Test-RunKey {
  Note 'Run-key persistence (adds then can remove an HKCU Run value)'
  reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v WatchMeTest /t REG_SZ /d "C:\Windows\System32\calc.exe" /f | Out-Null
  Ok 'Set HKCU\...\Run\WatchMeTest (Sysmon 13). Needs Sysmon monitoring Run keys (SwiftOnSecurity config does).'
}

# 5) LSASS access  -> Sysmon 10 -> WatchMe "LSASS process access" (T1003.001)
function Test-Lsass {
  Note 'LSASS access (lists LSASS loaded modules; does NOT read credentials)'
  # tasklist /m opens lsass with query+module-read to list DLLs. It cannot and does not read memory secrets.
  tasklist /m /fi "IMAGENAME eq lsass.exe" | Out-Null
  Ok 'Opened lsass.exe to enumerate modules (Sysmon 10 with a credential-access-style mask). No secrets are read.'
}

# 6) Defender detection  -> Defender 1116 -> WatchMe "DETECTED" + "Security product detection"
function Test-Defender {
  Note 'Defender detection via the EICAR test string (industry-standard, harmless)'
  $dir = 'C:\WatchMeTest'; New-Item -ItemType Directory -Force -Path $dir | Out-Null
  # EICAR built from parts so this script file itself is not flagged
  $eicar = 'X5O!P%@AP[4\PZX54(P^)7CC)7}' + '$' + 'EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
  try { Set-Content -Path "$dir\eicar.com" -Value $eicar -Encoding Ascii -NoNewline -ErrorAction Stop }
  catch { Warn 'Defender removed the EICAR file as it was written (that is the detection). Event 1116 should appear.' }
  Ok 'Dropped the EICAR test file. Defender logs event 1116/1117. (Real-time protection must be on.)'
}

# 7) Account lockout  -> Security 4740 (+ 4625) -> WatchMe "Repeated account lockouts"
function Test-Lockout {
  Note 'Account lockout (fails logons for a throwaway local account until it locks)'
  $u = 'watchmelab'
  if (-not (Get-LocalUser -Name $u -ErrorAction SilentlyContinue)) {
    New-LocalUser -Name $u -Password (ConvertTo-SecureString 'C0rrect-Horse!' -AsPlainText -Force) -AccountNeverExpires | Out-Null
  }
  Add-Type -Namespace Win32 -Name NA -MemberDefinition '[DllImport("advapi32.dll", SetLastError=true)] public static extern bool LogonUser(string u,string d,string p,int lt,int lp,out System.IntPtr t);'
  $t = [IntPtr]::Zero
  1..4 | ForEach-Object { [Win32.NA]::LogonUser($u, $env:COMPUTERNAME, 'WRONG-password', 2, 0, [ref]$t) | Out-Null }
  Ok "Failed 4 logons for '$u' (events 4625, then 4740 lockout)."
}

# 8) Special privileges  -> Security 4672 -> shown as privilege activity
function Test-Privilege {
  Note 'Special-privilege logon (4672)'
  # A new elevated logon token gets 4672. Launch an elevated whoami in a fresh logon.
  Start-Process -FilePath powershell -Verb RunAs -ArgumentList '-NoProfile','-Command','whoami /priv | Out-Null; Start-Sleep 1' -ErrorAction SilentlyContinue
  Ok 'Triggered an elevated logon (event 4672). Approve the UAC prompt if it appears.'
}

# 9) Audit log cleared  -> System 104 -> WatchMe "Audit log cleared" (T1070.001)
function Test-AuditClear {
  Note 'Audit-log-cleared (clears the low-value "Windows PowerShell" classic log, not Security)'
  wevtutil cl "Windows PowerShell"
  Ok 'Cleared the "Windows PowerShell" log (event 104). Reverting the snapshot restores it.'
}

# 10) USB device  -> shown as generic activity (no dedicated node yet)
function Test-Usb {
  Warn 'USB connect is a manual step: in VirtualBox, Devices > USB > pick a device (or toggle the shared one).'
  Warn 'It appears in WatchMe as generic activity on the host, not a dedicated node yet.'
}

# 11) Cloud sign-ins are NOT generated on this VM. See tools/lab/inject-cloud-events.sh (run on the host).
function Test-Cloud {
  Warn 'Cloud sign-ins (M365/Entra/AWS/Okta) do not exist on this endpoint.'
  Warn 'They come from cloud audit logs. For a lab test, run tools/lab/inject-cloud-events.sh on the host to index synthetic docs into Elasticsearch.'
}

function Do-Cleanup {
  Note 'Cleaning up test artifacts'
  sc.exe delete WatchMeTestSvc 2>$null | Out-Null
  schtasks /delete /tn 'WatchMeTestTask' /f 2>$null | Out-Null
  reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v WatchMeTest /f 2>$null | Out-Null
  Remove-Item 'C:\WatchMeTest' -Recurse -Force -ErrorAction SilentlyContinue
  Remove-LocalUser -Name 'watchmelab' -ErrorAction SilentlyContinue
  net accounts /lockoutthreshold:0 | Out-Null
  Ok 'Removed the test service, task, run key, folder and account. (Cleared logs are restored by the snapshot.)'
}

if ($Cleanup) { Do-Cleanup; return }

$map = @{
  software=${function:Test-Software}; service=${function:Test-Service}; scheduledtask=${function:Test-ScheduledTask};
  runkey=${function:Test-RunKey}; lsass=${function:Test-Lsass}; defender=${function:Test-Defender};
  lockout=${function:Test-Lockout}; privilege=${function:Test-Privilege}; auditclear=${function:Test-AuditClear};
  usb=${function:Test-Usb}; cloud=${function:Test-Cloud}
}
$run = if ($All) { $map.Keys } elseif ($Test) { $Test } else { Warn 'Pass -All or -Test <name,...>. Names: '+($map.Keys -join ', '); return }

Enable-Audit
foreach ($t in $run) { & $map[$t]; Start-Sleep -Milliseconds 400 }
Ok 'Done. Wait ~1 minute, then check WatchMe (open the VM user, or Ctrl+K host.name:"'+$env:COMPUTERNAME+'" -> Graph log search, Live on).'
Note 'Run  .\Test-WatchMeActivity.ps1 -Cleanup  when finished, or revert the clean-baseline snapshot.'
