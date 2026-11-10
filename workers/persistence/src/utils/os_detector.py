# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Operating System and Hostname detector for persistence analysis targets."""

from __future__ import annotations

from src.utils.models import AnalysisContext, AnalysisTarget


def _parse_os_family(content: str) -> str:
    """Parse an os-release/lsb-release style file into an OS family string.

    Prefers the machine-readable ``ID`` field, then ``ID_LIKE``, then ``NAME``
    (or ``DISTRIB_ID`` for lsb-release files). Returns "linux" when no useful
    identifier is present.

    Args:
        content: Raw text content of the release file.

    Returns:
        Lowercase OS family identifier (e.g. 'ubuntu', 'debian', 'rhel').
    """
    fields: dict[str, str] = {}
    for line in content.splitlines():
        clean = line.strip()
        if not clean or clean.startswith("#") or "=" not in clean:
            continue
        key, _, val = clean.partition("=")
        fields[key.strip()] = val.strip().strip("'").strip('"')

    for key in ("ID", "ID_LIKE", "NAME", "DISTRIB_ID"):
        value = fields.get(key, "").strip().lower()
        if not value:
            continue
        # ID_LIKE is a space-separated list; use the first entry.
        if key == "ID_LIKE":
            value = value.split()[0]
        return value

    return "linux"


def detect_os_and_hostname(target: AnalysisTarget) -> tuple[str, str]:
    """Detect operating system name and hostname from an AnalysisTarget.

    Args:
        target: The target filesystem abstraction (mounted image or extracted files).

    Returns:
        A tuple of (os_name, hostname), e.g. ('ubuntu', 'prod-web-01').
    """
    hostname = "unknown"
    hostname_content = target.read_text("/etc/hostname")
    if hostname_content:
        for line in hostname_content.splitlines():
            clean_line = line.strip()
            if clean_line and not clean_line.startswith("#"):
                hostname = clean_line
                break

    # Read os-release files (with lsb-release fallback) to detect the OS family.
    os_release = target.read_text("/etc/os-release")
    if not os_release:
        os_release = target.read_text("/usr/lib/os-release")
    if not os_release:
        os_release = target.read_text("/etc/lsb-release")

    # Persistence worker targets Linux artifacts; defaults to "linux".
    os_name = _parse_os_family(os_release) if os_release else "linux"

    return os_name, hostname


def build_analysis_context(target: AnalysisTarget) -> AnalysisContext:
    """Build an AnalysisContext from an AnalysisTarget by detecting OS and hostname.

    Args:
        target: The target filesystem abstraction.

    Returns:
        An AnalysisContext populated with target, detected os_name, and hostname.
    """
    os_name, hostname = detect_os_and_hostname(target)
    return AnalysisContext(target=target, os_name=os_name, hostname=hostname)


__all__ = [
    "build_analysis_context",
    "detect_os_and_hostname",
]
