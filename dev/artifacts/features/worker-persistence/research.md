---
slug: worker-persistence
issue:
created: 2026-11-10
by: hacktobeer (Ramses de Beer)
---
# Research: Add Linux persistence analyzer worker

Notes and findings on designing and building `openrelik-worker-persistence`.

## What I wanted to know

1. Which Linux persistence mechanisms and MITRE ATT&CK techniques require structural parsing rather than flat string matching?
2. How can the worker accept both raw forensic disk images and extracted or standalone files forwarded from upstream OpenRelik tasks?
3. How do we prevent malicious symlinks or relative paths inside a mounted disk image from escaping into the worker container's host filesystem?
4. How should cross-boundary execution (privileged system configurations invoking binaries in `/home/*`, `/tmp`, `/var/tmp`, or `/dev/shm`) be detected and ranked?
5. What output formats do downstream pipeline tasks and human analysts need in OpenRelik?

## What I found

### 1. Linux persistence vectors and MITRE ATT&CK coverage

Linux persistence spans system-wide configuration directories, user home directories, and authentication or dynamic-linker hooks. Parsing each format structurally extracts the execution context (`User`, schedule, options, target path) and reduces false positives compared to regex scans:

| Vector | MITRE ATT&CK | Target paths | What needs to be parsed |
| --- | --- | --- | --- |
| Systemd services and timers | `T1543.002` | `/etc/systemd/system/**`, `/lib/systemd/system/**`, `/usr/lib/systemd/system/**`, `~/.config/systemd/user/**`, `~/.local/share/systemd/user/**` | INI-style unit directives (`ExecStart`, `ExecStartPre`, `ExecStartPost`, `ExecStop`, `ExecReload`, `ConditionPathExists`, `User`, `Group`, `WorkingDirectory`, `OnCalendar`), including multi-line continuations and multiple `ExecStart=` entries. |
| Cron and anacron | `T1053.003` | `/etc/crontab`, `/etc/cron.d/*`, `/etc/cron.{daily,hourly,weekly,monthly}/*`, `/etc/anacrontab`, `/var/spool/cron/crontabs/*`, `/var/spool/cron/*` | 5-field schedules and `@reboot`/`@hourly` macros, executing user field (on system crontabs), environment assignments, and shell script bodies in `cron.*` directories. |
| Shell profiles and RC scripts | `T1546.004` | `/etc/profile`, `/etc/bash.bashrc`, `/etc/bashrc`, `/etc/profile.d/*`, `/etc/zsh/*`, `~/.bashrc`, `~/.bash_profile`, `~/.profile`, `~/.zshrc`, `~/.bash_logout` | Appended commands, `PROMPT_COMMAND` hooks, download cradles (`curl`/`wget` piped to a shell), reverse shells (`/dev/tcp`, `nc -e`, `mkfifo`, `socat`, inline `python -c` socket calls), and base64-encoded command blocks (`echo <b64> \| base64 -d \| sh`) that can be decoded into `decoded_payload`. |
| SSH authorized keys and `sshd_config` | `T1098.004` | `/root/.ssh/authorized_keys*`, `/home/*/.ssh/authorized_keys*`, `/etc/ssh/sshd_config`, `/etc/ssh/sshd_config.d/*` | Authorized key options (`command="..."` forced execution, forwarding options), key types, SHA-256 fingerprints, key comments, and `sshd_config` overrides (`PermitRootLogin`, `AuthorizedKeysFile`, `AuthorizedKeysCommand`, `PermitEmptyPasswords`). |
| SysV init and startup scripts | `T1037.004` | `/etc/rc.local`, `/etc/rc.d/rc.local`, `/etc/init.d/*`, `/etc/rc[0-6S].d/*` | Active commands before `exit 0` in `rc.local`, runlevel symlinks (`S*`, `K*`) and orphan symlink targets, and suspicious execution paths inside init scripts. |
| Dynamic linker preloading | `T1574.006` | `/etc/ld.so.preload`, `/etc/ld.so.conf`, `/etc/ld.so.conf.d/*` | Shared objects listed in `/etc/ld.so.preload` and non-standard library search directories in `ld.so.conf.d/`. Standard Linux installs rarely populate `/etc/ld.so.preload`, so any entry there warrants `CRITICAL` severity. |
| Sudoers and PAM modules | `T1548.003`, `T1556.003` | `/etc/sudoers`, `/etc/sudoers.d/*`, `/etc/pam.d/*` | `NOPASSWD` grants, sudo rules referencing scripts in `/home/*` or `/tmp/*`, `pam_exec.so` command hooks, `pam_permit.so` authentication bypasses, and PAM shared objects outside `/lib*/security`. |
| XDG desktop autostart | `T1547.013` | `/etc/xdg/autostart/*.desktop`, `/root/.config/autostart/*.desktop`, `/home/*/.config/autostart/*.desktop` | `[Desktop Entry]` keys (`Name`, `Exec`, `TryExec`, `Terminal`, `Type`, `Hidden`), flagging hidden entries (`Hidden=true` or `NoDisplay=true` combined with suspicious commands), temporary/user paths, and encoded payloads. |

### 2. Dual-input handling: disk images and extracted files

In OpenRelik workflows, a worker may receive either a full disk image at the start of a pipeline or individual files extracted by an upstream worker (`workers/extraction`):

- **Disk images**: `openrelik_worker_common.file_utils.is_disk_image` identifies disk image extensions (`.img`, `.raw`, `.dd`, `.qcow`, `.qcow2`, `.qcow3`, `.e01`, `.ex01`). Following `workers/extraction/src/extractfiles.py`, `BlockDevice(image_path=..., min_partition_size=1)` in `openrelik_worker_common.mount_utils` sets up loop/NBD devices and mounts partitions read-only. Calling `bd.umount()` inside a `finally` block guarantees cleanup even if a parser raises an exception.
- **Extracted files with `original_path`**: Upstream extraction tasks populate `original_path` (either on the file dict or under `meta.original_path`). Mapping `normalize_virtual_path(original_path)` to the local file path reconstructs the virtual directory tree in memory without copying files.
- **Loose standalone files**: When an analyst uploads an individual file (such as a single `.bashrc`, `authorized_keys`, or `nginx-helper.service`) without `original_path`, filename patterns and a 4 KB content sniffer (`[Unit]`, `[Service]`, `[Timer]`, `[Desktop Entry]`, `ssh-rsa`/`ssh-ed25519`, cron schedule lines, `pam_*.so`, `NOPASSWD`) route the file to a canonical virtual path (for example `/etc/systemd/system/<name>` or `/home/unknown/.bashrc`) so all downstream parsers and cross-boundary checks work identically.
- **`AnalysisTarget` abstraction**: Providing a single `AnalysisTarget` interface (`exists`, `read_text`, `read_bytes`, `glob`, `resolve_symlink`, `stat_owner`) decouples the parsers from how the input was supplied.

### 3. Forensic containment and path traversal protection

Mounting an untrusted disk image exposes the worker to crafted symlinks (such as `/mnt/image/etc/rc.local -> /etc/shadow`) and `..` path traversal segments:

- `safe_resolve_path(root_path, virtual_path)` normalizes the path and checks `os.path.commonpath([root_abs, full_abs]) == root_abs`, raising `PathTraversalSecurityError` if a path escapes the mount root.
- `safe_resolve_symlink` reads `os.readlink`, resolves relative targets against the symlink's parent directory inside `root_path`, and verifies containment via `commonpath` before returning the target virtual path.
- File reads enforce a default size cap (`max_bytes = 1_048_576`) so large binary files or device nodes cannot exhaust worker memory.

### 4. Cross-boundary correlation and scoring

A recurring privilege-escalation and persistence pattern on Linux hosts is a root-owned service, timer, cron job, init script, sudoers rule, or global XDG autostart entry pointing to a script or binary inside an unprivileged user's home directory (`/home/<user>/...`) or a world-writable temporary path (`/tmp`, `/var/tmp`, `/dev/shm`):

- `linux_cross_boundary.py` inspects existing parser findings from system configuration prefixes (`/etc/`, `/lib/`, `/usr/lib/`, `/var/spool/cron/`, `/var/cron/`) as well as raw system configuration files on the target. When a root-executed system configuration references a binary under `/home/<user>/...` or `/tmp`/`/var/tmp`/`/dev/shm`, it escalates the finding to `CRITICAL`, sets category `cross_boundary_<type>`, records `target_binary_owner` and `target_binary_path`, and attaches `SYSTEM_SERVICE_POINTS_TO_USER_HOME` / `CROSS_BOUNDARY_EXECUTION` flags.
- `scoring_engine.py` deduplicates findings by `(category, path, details_signature)`, evaluates flag sets into `CRITICAL`, `HIGH`, `MEDIUM`, and `INFO`, sorts deterministically by severity and path, and assigns sequential IDs (`FINDING-001`, `FINDING-002`, ...).

### 5. Output deliverables and OS-extensible layout

- **JSON artifact (`persistence_report.json`)**: Written via `create_output_file` with `data_type="openrelik:persistence:report:json"`, containing `meta` (`os`, `hostname`, `analysis_timestamp`, `total_findings`) and `findings` (`id`, `category`, `risk_level`, `technique_id`, `path`, `details`, `raw_content`, `decoded_payload`).
- **OpenRelik UI Task Report**: Built with `openrelik_worker_common.reporting.Report` and `Priority`, rendering a findings summary table, detailed sections for critical/high and medium/info findings (with MITRE ATT&CK links and decoded payload previews), and recommended next actions for the analyst.
- **OS-prefixed module layout**: Naming the Linux modules `src/utils/linux_*.py` behind `os_detector.py` leaves a clear extension path for future `windows_*.py` and `macos_*.py` modules without restructuring the worker.

## Sources

- `workers/extraction/src/extractfiles.py` and `libs/worker-common/openrelik_worker_common/mount_utils.py` (`BlockDevice` setup, mounting, and cleanup)
- `workers/strings/src/app.py` and `workers/strings/src/tasks.py` (Celery app, task metadata, and OpenTelemetry instrumentation)
- `libs/worker-common/openrelik_worker_common/reporting.py` (`Report` and `Priority` classes)
- MITRE ATT&CK Enterprise Matrix (Linux Persistence & Privilege Escalation): `T1543.002`, `T1053.003`, `T1546.004`, `T1098.004`, `T1037.004`, `T1574.006`, `T1548.003`, `T1556.003`, `T1547.013`
