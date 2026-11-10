---
slug: worker-persistence
issue:
created: 2026-11-10
by: hacktobeer (Ramses de Beer)
---
# Spec: Add Linux persistence analyzer worker

Implements idea.md.

## Scope

- Create the `openrelik-worker-persistence` worker in `workers/persistence/` with Celery app setup (`src/app.py`), task definition (`src/tasks.py`), container build (`Dockerfile`), marketplace metadata (`openrelik.yaml`), and `uv` project configuration (`pyproject.toml`, `uv.lock`).
- Implement `AnalysisTarget` and `PathTraversalSecurityError` in `src/utils/models.py` and dual-input target resolution (`resolve_targets`) in `src/utils/target_resolver.py` supporting mounted disk images via `BlockDevice` as well as extracted or standalone files via `original_path` mapping and filename/content heuristics.
- Implement OS and hostname detection in `src/utils/os_detector.py`.
- Implement eight Linux persistence vector parsers (`linux_systemd.py`, `linux_cron.py`, `linux_shell_profiles.py`, `linux_ssh.py`, `linux_init.py`, `linux_ld_preload.py`, `linux_pam_sudoers.py`, `linux_autostart.py`), cross-boundary execution correlation (`linux_cross_boundary.py`), and the Linux analysis coordinator (`linux_analyzer.py`).
- Implement risk evaluation, deduplication, and sequential finding ID assignment in `src/utils/scoring_engine.py`.
- Implement report generation in `src/utils/report_generator.py` producing both `persistence_report.json` (`openrelik:persistence:report:json`) and an OpenRelik Markdown `Report`.
- Support `min_risk_level` and `include_raw_content` task configuration options in `src/tasks.py`.
- Add unit tests in `workers/persistence/tests/` covering all modules and task execution.
- Out of scope: Windows and macOS persistence parsers.

## Requirements

- R1: `workers/persistence/` is structured as an OpenRelik Celery worker package (`openrelik-worker-persistence`) with `Dockerfile`, `openrelik.yaml`, `pyproject.toml`, `uv.lock`, `README.md`, `src/app.py`, and `src/tasks.py` registering task `openrelik-worker-persistence.tasks.persistence`.
- R2: `src/utils/models.py` defines `RiskLevel` (`CRITICAL`, `HIGH`, `MEDIUM`, `INFO`), `Finding`, `ReportMeta`, `AnalysisContext`, `AnalysisTarget`, and `PathTraversalSecurityError`, enforcing via `os.path.commonpath` that file reads and resolved symlinks never escape `root_path` and capping file reads at `max_bytes` (default 1 MiB).
- R3: `src/utils/target_resolver.py` resolves disk images (identified via `is_disk_image`) by mounting partitions with `BlockDevice(image_path=..., min_partition_size=1)` and always calling `bd.umount()` in a `finally` block, and resolves extracted or standalone files into an `AnalysisTarget` using `original_path` metadata or filename and content heuristics.
- R4: `src/utils/os_detector.py` detects the target OS family and reads the hostname from `/etc/hostname` (with fallbacks to `/etc/os-release`, `/usr/lib/os-release`, `/etc/lsb-release`, and `"unknown"`).
- R5: The Linux persistence parsers inspect and extract findings with MITRE ATT&CK technique IDs and heuristic flags for:
  - Systemd system and user `.service` and `.timer` units (`T1543.002` in `src/utils/linux_systemd.py`)
  - System crontabs, `cron.*` directories, `anacrontab`, and user crontabs (`T1053.003` in `src/utils/linux_cron.py`)
  - Global and user shell profiles and RC files, including inline base64 payload decoding into `decoded_payload` (`T1546.004` in `src/utils/linux_shell_profiles.py`)
  - Root and user SSH `authorized_keys` (including `command="..."` forced execution) and `sshd_config` directives (`T1098.004` in `src/utils/linux_ssh.py`)
  - `/etc/rc.local`, `/etc/init.d/*`, and `/etc/rc[0-6S].d/*` runlevel scripts and symlinks (`T1037.004` in `src/utils/linux_init.py`)
  - `/etc/ld.so.preload` and non-standard library paths in `/etc/ld.so.conf*` (`T1574.006` in `src/utils/linux_ld_preload.py`)
  - `/etc/sudoers*` privilege rules (`T1548.003`) and `/etc/pam.d/*` authentication modules (`T1556.003` in `src/utils/linux_pam_sudoers.py`)
  - System and user XDG `.desktop` autostart entries (`T1547.013` in `src/utils/linux_autostart.py`)
- R6: `src/utils/linux_cross_boundary.py` detects privilege boundary violations where system-level configurations (`/etc/*`, `/lib/*`, `/usr/lib/*`, `/var/spool/cron/*`, `/var/cron/*`) execute binaries or scripts inside `/home/<user>/*`, `/tmp/*`, `/var/tmp/*`, or `/dev/shm/*`, emitting `cross_boundary_*` findings with `CRITICAL` severity.
- R7: `src/utils/scoring_engine.py` evaluates finding flags and categories into `RiskLevel` values, deduplicates findings, sorts them by severity (`CRITICAL`, `HIGH`, `MEDIUM`, `INFO`), and assigns sequential IDs (`FINDING-001`, `FINDING-002`, ...).
- R8: `src/utils/linux_analyzer.py` runs all Linux parsers and cross-boundary correlation across targets, isolates individual parser exceptions so one parser failure does not abort remaining parsers, applies optional `min_risk_level` filtering, and returns `(ReportMeta, list[Finding])`.
- R9: `src/utils/report_generator.py` writes `persistence_report.json` containing `meta` and `findings` and builds an OpenRelik `Report` with summary counts, severity sections, MITRE ATT&CK links, configuration/decoded payload blocks, and analyst recommendations; `src/tasks.py` applies `min_risk_level` and `include_raw_content`, emits `task-progress`, and returns `create_task_result`.
- R10: Unit tests in `workers/persistence/tests/` verify data models, path traversal guards, target resolution, OS detection, all eight Linux parsers, cross-boundary correlation, scoring, report generation, and Celery task execution via `uv run pytest`.

## Tasks

- [x] T1: Scaffold `workers/persistence/` with `pyproject.toml`, `uv.lock`, `Dockerfile`, `openrelik.yaml`, `README.md`, `LICENSE`, `.python-version`, `.coveragerc`, and `.dockerignore` (R1).
- [x] T2: Implement core data models, `AnalysisTarget`, and path-traversal protection in `workers/persistence/src/utils/models.py` and OS/hostname detection in `workers/persistence/src/utils/os_detector.py`, with unit tests in `tests/test_models.py` and `tests/test_os_detector.py` (R2, R4, R10).
- [x] T3: Implement dual-input resolution and `BlockDevice` mount lifecycle in `workers/persistence/src/utils/target_resolver.py`, with unit tests in `tests/test_target_resolver.py` (R3, R10).
- [x] T4: Implement systemd (`linux_systemd.py`), cron/anacron (`linux_cron.py`), shell profile (`linux_shell_profiles.py`), and SSH (`linux_ssh.py`) parsers in `workers/persistence/src/utils/`, with unit tests in `tests/test_linux_systemd.py`, `tests/test_linux_cron.py`, `tests/test_linux_shell_profiles.py`, and `tests/test_linux_ssh.py` (R5, R10).
- [x] T5: Implement SysV init/`rc.local` (`linux_init.py`), dynamic linker preload (`linux_ld_preload.py`), sudoers/PAM (`linux_pam_sudoers.py`), and XDG autostart (`linux_autostart.py`) parsers in `workers/persistence/src/utils/`, with unit tests in `tests/test_linux_init.py`, `tests/test_linux_ld_preload.py`, `tests/test_linux_pam_sudoers.py`, and `tests/test_linux_autostart.py` (R5, R10).
- [x] T6: Implement cross-boundary correlation (`linux_cross_boundary.py`), risk scoring and deduplication (`scoring_engine.py`), and the Linux analysis orchestrator (`linux_analyzer.py`), with unit tests in `tests/test_linux_cross_boundary.py`, `tests/test_scoring_engine.py`, and `tests/test_linux_analyzer.py` (R6, R7, R8, R10).
- [x] T7: Implement JSON and Markdown report generation in `workers/persistence/src/utils/report_generator.py` and Celery app/task orchestration in `workers/persistence/src/app.py` and `workers/persistence/src/tasks.py`, with unit tests in `tests/test_report_generator.py` and `tests/test_tasks.py` (R1, R9, R10).
- [x] T8: Run `uv run pytest` and `uv run ruff check` in `workers/persistence/` to verify all unit tests and lint checks pass (R10).

## Tests

- R1, R9: `workers/persistence/tests/test_tasks.py` and `workers/persistence/tests/test_report_generator.py` verify Celery task registration, `min_risk_level` and `include_raw_content` handling, `persistence_report.json` schema output, and OpenRelik Markdown `Report` generation.
- R2: `workers/persistence/tests/test_models.py` verifies `Finding` and `ReportMeta` serialization, virtual path normalization, `PathTraversalSecurityError` on path and symlink escapes, and bounded file reads.
- R3: `workers/persistence/tests/test_target_resolver.py` verifies `is_disk_image` routing, `BlockDevice.setup()` / `mount()` / `umount()` cleanup in `finally` blocks (including on exception), `original_path` virtual mapping, and standalone file heuristic routing.
- R4: `workers/persistence/tests/test_os_detector.py` verifies hostname and OS detection from `/etc/hostname` and `/etc/os-release` with fallback handling.
- R5: `workers/persistence/tests/test_linux_systemd.py`, `test_linux_cron.py`, `test_linux_shell_profiles.py`, `test_linux_ssh.py`, `test_linux_init.py`, `test_linux_ld_preload.py`, `test_linux_pam_sudoers.py`, and `test_linux_autostart.py` verify parser extraction, heuristic flags, and base64 payload decoding.
- R6: `workers/persistence/tests/test_linux_cross_boundary.py` verifies detection and `CRITICAL` escalation when root/system configurations reference executables in `/home/<user>` or temporary directories.
- R7, R8: `workers/persistence/tests/test_scoring_engine.py` and `workers/persistence/tests/test_linux_analyzer.py` verify severity calculation, deduplication, deterministic sorting, sequential `FINDING-NNN` numbering, parser error isolation, and `min_risk_level` filtering.
- R10: Execute `uv run pytest` in `workers/persistence/` and verify all test suites pass.

## Rollout

New worker package (`workers/persistence/`). No database migrations or server schema changes required.
