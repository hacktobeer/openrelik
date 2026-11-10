---
slug: worker-persistence
issue:
created: 2026-11-10
by: hacktobeer (Ramses de Beer)
---
# Review Round 1

Date: 2026-11-10
Checks run:
- uv run pytest in workers/persistence (231 passed)
- uv run ruff check in workers/persistence (passed)
- uv run ruff format --check in workers/persistence (passed)
- uv run --python 3.12 .github/scripts/check-versions.py (2 errors in workers/persistence/pyproject.toml)

What this change does: Adds the `openrelik-worker-persistence` Celery worker to analyze Linux persistence artifacts across mounted disk images and extracted files. It implements eight forensic parsers (systemd, cron, shell profiles, SSH, init/rc.local, ld.so preload, PAM/sudoers, XDG autostart), cross-boundary privilege escalation correlation, risk scoring, and JSON/Markdown report generation.

## Requirements
- R1: done
- R2: done
- R3: done
- R4: done
- R5: done
- R6: done
- R7: done
- R8: done
- R9: done
- R10: done

## Must fix

1. **Dependency version specifiers break repo check-versions script** (`workers/persistence/pyproject.toml:9-14`)
   - **What this is:** The worker project definition uses `>=` constraints and defines version `0.1.0`.
   - **Problem:** `.github/scripts/check-versions.py` fails with 2 errors because repository rules require worker dependencies on `openrelik-worker-common` and `openrelik-common` to use `~=X.Y.N` matching the worker's minor version (`0.18.0`).
   - **Fix:** Update `version = "0.18.0"`, `requires-python = ">=3.12,<4.0"`, and set dependencies to `openrelik-worker-common~=0.18.0` and `openrelik-common~=0.18.0`.
   - **If we skip it:** Repository version checks and CI validation will fail.

2. **Absolute image symlinks rejected if target path exists on host** (`workers/persistence/src/utils/models.py:246-254`)
   - **What this is:** `safe_resolve_symlink` checks whether `os.path.realpath(physical_path)` exists outside the mount root.
   - **Problem:** Absolute symlinks inside a forensic disk image (such as `/etc/rc3.d/S01ssh -> /etc/init.d/ssh` or `/etc/init.d/sh -> /bin/sh`) resolve against the host container's root `/`. If that file exists inside the worker container (such as `/bin/sh`), `os.path.exists(real_dest)` is true and `commonpath != root_abs`, causing `safe_resolve_symlink` to incorrectly return `None` and treat the valid symlink as a traversal attack.
   - **Fix:** Delete lines 247-254; lines 256-263 already resolve the symlink target inside the virtual filesystem tree and verify containment via `safe_resolve_path`.
   - **If we skip it:** Legitimate absolute symlinks on disk images fail resolution whenever a file with the same path exists inside the worker container.

3. **Unbounded recursive scan and wildcard slash traversal in AnalysisTarget.glob** (`workers/persistence/src/utils/models.py:408-428`)
   - **What this is:** `AnalysisTarget.glob` finds the literal directory before the first wildcard and runs an unpruned `os.walk` across that subtree, testing matches with `fnmatch.fnmatch`.
   - **Problem:** `fnmatch` translates `*` to `.*`, so `*` matches `/` across directory separators (for example, `/home/*/.bashrc` matches `/home/user/deep/repo/.bashrc`). Furthermore, for `/home/*` patterns, `os.walk` recursively traverses the entire `/home` directory tree down to arbitrary depth 12 separate times across the parsers, causing massive I/O bottlenecks on large disk images.
   - **Fix:** Use standard library `pathlib.Path(root_abs).glob()` (which does not cross `/` on single `*`) validated with `commonpath`, or prune `dirnames` in `os.walk` when depth exceeds the pattern segment count.
   - **If we skip it:** Processing disk images with large user directories will stall Celery workers, and nested files inside git repos or caches will produce false positive matches.

4. **Absolute file symlinks on disk images cannot be read** (`workers/persistence/src/utils/models.py:151-177`)
   - **What this is:** `safe_read_bytes` performs containment validation using `os.path.realpath(physical_path)`.
   - **Problem:** When an artifact file on a mounted image is an absolute symlink (such as `/etc/os-release -> /usr/lib/os-release`), `os.path.realpath` resolves the symlink against the container host root rather than the image root. As a result, `commonpath` detects an escape and returns `None`, making the file unreadable even though it exists inside the image.
   - **Fix:** In `safe_read_bytes`, if `os.path.islink(physical_path)` is true, resolve the symlink virtually using `safe_resolve_symlink(root_path, virtual_path)` and read the resolved path instead of rejecting it.
   - **If we skip it:** Common Linux distribution configurations where `/etc/os-release` or `/etc/rc.local` are absolute symlinks cannot be read, breaking OS detection and parser extraction.

## Should fix

5. **Cross-boundary regex scans unparsed content and comments** (`workers/persistence/src/utils/linux_cross_boundary.py:387-430, 480-530`)
   - **What this is:** Cross-boundary correlation scans raw `content` and `raw_content` strings with `extract_user_home_path` and `extract_temp_path`.
   - **Problem:** Comments (such as `# Example: /home/user/script.sh`) or non-executable environment settings (like `Environment="TMPDIR=/tmp"`) match the regexes, causing benign system services to be falsely escalated to `CRITICAL` severity with `SYSTEM_SERVICE_POINTS_TO_USER_HOME`.
   - **Fix:** Inspect only structured command directives (`exec_start`, `command`, `target_binary_path`), and strip comments (lines starting with `#`) before checking raw lines.
   - **If we skip it:** Benign services with comments mentioning `/home/` or setting `TMPDIR` will trigger false positive `CRITICAL` alerts.

6. **Missing parser flags in scoring engine flag set** (`workers/persistence/src/utils/scoring_engine.py:20-35`)
   - **What this is:** `scoring_engine.py` defines `CRITICAL_FLAGS` to evaluate finding risk levels.
   - **Problem:** Flags emitted by several parsers—`SYSTEM_INIT_POINTS_TO_USER_HOME`, `SYSTEM_PAM_POINTS_TO_USER_HOME`, `SYSTEM_SUDOERS_POINTS_TO_USER_HOME`, and `SYSTEM_PROFILE_POINTS_TO_USER_HOME`—are omitted from `CRITICAL_FLAGS`.
   - **Fix:** Add these flags to `CRITICAL_FLAGS` in `scoring_engine.py`.
   - **If we skip it:** Findings evaluated directly by `evaluate_risk_level` without cross-boundary promotion will be under-scored as `INFO`.

## Nice to have

7. **Ad-hoc isinstance dispatch in LinuxPamSudoersParser** (`workers/persistence/src/utils/linux_pam_sudoers.py:417-434`)
   - **What this is:** `LinuxPamSudoersParser.parse` checks `if isinstance(self, AnalysisTarget)` to handle class-level invocations.
   - **Problem:** The check compensates for not decorating `parse` with `@classmethod` and preserves unused instance state `self.target`.
   - **Fix:** Declare `@classmethod def parse(cls, target: AnalysisTarget) -> list[Finding]:` and return `analyze_pam_sudoers(target)`.
   - **If we skip it:** Unnecessary runtime type inspection remains in the codebase.

8. **Over-abstracted FlexibleBool class** (`workers/persistence/src/utils/linux_autostart.py:100-128`)
   - **What this is:** A 29-line custom `FlexibleBool(str)` subclass to compare desktop entry boolean values.
   - **Problem:** Unnecessary custom class to check if a string equals `"true"`, `"1"`, or `"yes"`.
   - **Fix:** Replace `FlexibleBool` with a 2-line helper function or direct string comparison.
   - **If we skip it:** Extra boilerplate code must be maintained.

Verdict: fix 1, 2, 3, and 4 first.

---

# Review Round 2

Date: 2026-11-10
Checks run:
- uv run pytest in workers/persistence (244 passed)
- uv run ruff check in workers/persistence (passed)
- uv run ruff format --check in workers/persistence (passed)
- uv run --python 3.12 .github/scripts/check-versions.py (0 errors, 27 warnings)

What this change does:
Adds the `openrelik-worker-persistence` Celery worker to analyze Linux persistence artifacts across mounted disk images and extracted files. It inspects systemd units, crontabs, shell profiles, SSH configurations, SysV init scripts, dynamic linker preloads, PAM/sudoers rules, and XDG autostart entries, correlating cross-boundary privilege escalation to output structured JSON and Markdown reports.

## Requirements
- R1: done
- R2: done
- R3: done
- R4: done
- R5: done
- R6: done
- R7: done
- R8: done
- R9: done
- R10: done

Verdict: LGTM

Checked path traversal containment, BlockDevice mount/unmount lifecycles, memory safety on bounded reads, parser threat heuristics, scoring deduplication, report generation, and all 244 unit tests.
