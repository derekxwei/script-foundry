# BastionAudit

BastionAudit is a Bash-based Linux security assessment and basic hardening tool created for IS2083 Advanced Scripting Lab 1. It collects common host security information, performs a few practical security checks, enables a default-deny UFW firewall policy, calculates a simple security score, and writes the results to a timestamped report.

## Features

- Displays startup and completion dialogs with `zenity`
- Creates a timestamped report under `~/BastionAudit_reports/`
- Records OS, uptime, disk usage, privileged accounts, sudo-group membership, and pending package upgrades
- Reports process counts, top CPU/memory processes, and listening network services
- Demonstrates process control by starting and terminating a temporary background process
- Audits world-writable files, SUID programs, and permissions on `/etc/passwd` and `/etc/shadow`
- Enables UFW with default-deny incoming and default-allow outgoing policies
- Counts failed SSH logins and accounts with empty passwords
- Produces a security score and rating
- Locks each report to owner-only permissions (`chmod 600`)

## Requirements

BastionAudit is written for a Debian-based Linux desktop such as Ubuntu or Kali Linux.

Install the required packages before running it:

```bash
sudo apt update
sudo apt install -y zenity ufw
```

## Usage

```bash
chmod +x assessment_tool.sh
./assessment_tool.sh
```

Enter your sudo password when prompted. The script caches sudo authorization once for the privileged checks.

Each run creates a new report in:

```text
~/BastionAudit_reports/
```

## Verify a Run

```bash
TOOL_NAME="BastionAudit"
ls -ld "$HOME/${TOOL_NAME}_reports"
ls -l "$HOME/${TOOL_NAME}_reports/"
grep -E "System administration|Process control|permission audit|Hardening|Security score" \
  "$HOME/${TOOL_NAME}_reports/"report_*.txt
grep "Security score" "$HOME/${TOOL_NAME}_reports/"report_*.txt
sudo ufw status
ls -l "$HOME/${TOOL_NAME}_reports/"report_*.txt
pgrep -a sleep
```

A successful run should show the report directory and timestamped report, all required report sections, a security score, an active firewall, report permissions of `-rw-------`, and no leftover 120-second watcher process.

## Security / Privacy Note

The generated reports may contain host information, usernames, process details, and listening services. They are intentionally excluded from Git with `.gitignore` and should not be published.

## Course / Development Note

This project was built from the IS2083 Lab 1 course requirements. AI assistance was used to help draft and review portions of the Bash implementation and documentation. The student is responsible for reviewing, testing, and understanding the final code and its effects before submission.
