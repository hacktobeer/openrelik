---
slug: worker-persistence
issue:
created: 2026-11-10
by: hacktobeer (Ramses de Beer)
---
# Add Linux persistence analyzer worker

## Problem

Hunting for persistence mechanisms on Linux disk images or extracted file collections requires analysts to manually inspect dozens of configuration files across `/etc`, `/lib`, `/var/spool`, and user home directories, or rely on broad string and regex searches. Raw text searches miss structural context, such as a root-owned systemd unit or system crontab configured to execute a script inside an unprivileged user's home directory or a world-writable temporary path (`/tmp`, `/var/tmp`, `/dev/shm`). Analysts also have to manually decode obfuscated shell payloads and piece together findings across separate files.

## Proposal

Add a persistence analyzer worker (`openrelik-worker-persistence`) in `workers/persistence/` that semantically parses Linux persistence locations across mounted disk images and extracted or standalone artifact files. The worker inspects systemd units and timers, crontabs and anacrontab, shell profiles and RC scripts, SSH authorized keys and `sshd_config`, SysV init and `rc.local` scripts, dynamic linker preload configurations, sudoers and PAM modules, and XDG desktop autostart entries. It correlates cross-boundary execution where privileged system configurations invoke binaries in user-writable or temporary directories, scores findings into `CRITICAL`, `HIGH`, `MEDIUM`, and `INFO` risk levels with MITRE ATT&CK technique mappings, and produces both a structured `persistence_report.json` output file and a Markdown task report for the OpenRelik UI.

## Users

Forensic analysts and incident responders triaging Linux disk images, archives, or collected configuration artifacts in OpenRelik workflows.

## Open questions

- None.
