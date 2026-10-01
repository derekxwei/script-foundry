# WinGuard Windows Hardening Tool

WinGuard is a PowerShell tool for auditing and hardening a Windows 11 Enterprise practice VM. It groups 10 baseline checks and 5 advanced checks, prints a weighted score, and writes timestamped text reports. Apply mode records a BEFORE audit, attempts fixes for failing controls, then records an AFTER audit.

## Requirements

- Windows 11 Enterprise practice VM and Windows PowerShell 5.1
- Administrator PowerShell for Apply mode
- A clean VM snapshot before changing settings
- An English Windows installation for the `net accounts` parsing used by the password and lockout checks

Do not run Apply on a production machine. The tool changes local security settings and has no automated undo mode. It attempts a Windows restore point, but a VM snapshot is the more dependable rollback for this lab.

## Run

Clone this repository, then copy `winguard/Harden-Windows.ps1` into a folder in the VM. From an elevated Windows PowerShell window in that folder:

```powershell
.\Harden-Windows.ps1
.\Harden-Windows.ps1 -Mode Apply
```

Audit mode reads settings, prints the grouped results, and writes a report under `%USERPROFILE%\WinGuard_reports`. Apply mode changes failing settings that have remediation blocks, then rechecks them and writes a BEFORE/AFTER report. BitLocker is audit only; the script does not enable encryption or manage a recovery key.

The checks cover SMBv1, SMB signing, NTLM policy, UAC, password length, account lockout, firewall profiles, Defender real-time protection, Guest account, RDP Network Level Authentication, Defender PUA protection, an Office child-process ASR rule, PowerShell script block logging, LSA protection, and BitLocker status.

## Observed VM result

In the Windows 11 Enterprise lab VM, the captured report shows the score rising from **58/100** to **96/100**. After Apply, 10/10 baseline checks and 4/5 advanced checks reported PASS. BitLocker stayed off because its control is audit only. A separate firewall spot check returned `True` for all three profiles. Generated reports are excluded from this public repository because they can contain host details.

The PowerShell source passed a syntax parse with no errors. LSA protection was set to `RunAsPPL=1`, but the lab output notes that a reboot is required; effective protection after reboot has not been independently verified. Some Defender settings may be controlled by Tamper Protection or management policy on other machines.

## AI assistance

OpenAI Codex helped draft the 13 checks, review the lab instructions, and prepare this documentation. The student ran the tool in the practice VM and supplied the resulting screenshots and report. Anyone reusing it should review each command and validate its effect in their own authorized test environment.

