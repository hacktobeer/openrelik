# Copyright 2024 Google LLC
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
"""Data models, enums, and safe filesystem abstractions for persistence analysis."""

from __future__ import annotations

import os
import posixpath
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class PathTraversalSecurityError(Exception):
    """Raised when a resolved path attempts to escape the root mountpoint/directory."""


class RiskLevel(str, Enum):
    """Forensic risk severity level for persistence findings."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    INFO = "INFO"


@dataclass
class Finding:
    """Represents an identified persistence artifact or security anomaly."""

    id: str = ""
    category: str = ""
    risk_level: RiskLevel = RiskLevel.INFO
    technique_id: str = ""
    path: str = ""
    details: dict[str, Any] = field(default_factory=dict)
    raw_content: str | None = None
    decoded_payload: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert finding to dictionary representation.

        Returns:
            Dictionary representation of the finding.
        """
        return {
            "id": self.id,
            "category": self.category,
            "risk_level": (
                self.risk_level.value
                if isinstance(self.risk_level, RiskLevel)
                else str(self.risk_level)
            ),
            "technique_id": self.technique_id,
            "path": self.path,
            "details": self.details,
            "raw_content": self.raw_content,
            "decoded_payload": self.decoded_payload,
        }


@dataclass
class ReportMeta:
    """Metadata summary header for persistence analysis reports."""

    os: str = "linux"
    hostname: str = "unknown"
    analysis_timestamp: str = ""
    total_findings: int = 0

    def to_dict(self) -> dict[str, Any]:
        """Convert report metadata to dictionary representation.

        Returns:
            Dictionary representation of the report metadata.
        """
        return {
            "os": self.os,
            "hostname": self.hostname,
            "analysis_timestamp": self.analysis_timestamp,
            "total_findings": self.total_findings,
        }


def normalize_virtual_path(path: str) -> str:
    """Normalize a virtual path to POSIX format with a leading slash.

    Safely handles relative segments and prevents directory traversal.

    Args:
        path: Virtual path string to normalize.

    Returns:
        Normalized absolute POSIX virtual path with a leading slash.
    """
    if not path:
        return "/"
    clean = path.replace("\\", "/")
    parts = [p for p in clean.split("/") if p and p != "."]
    safe_parts: list[str] = []
    for part in parts:
        if part == "..":
            if safe_parts:
                safe_parts.pop()
        else:
            safe_parts.append(part)
    return "/" + "/".join(safe_parts)


def safe_resolve_path(root_path: str, virtual_path: str) -> str:
    """Safely resolve a virtual path inside a root directory, preventing directory traversal.

    Args:
        root_path: Local filesystem path representing root of mounted image or folder.
        virtual_path: Virtual path of target file (e.g. '/etc/systemd/system/foo.service').

    Returns:
        Canonical absolute physical path on local filesystem.

    Raises:
        PathTraversalSecurityError: If the resolved path escapes root_path.
    """
    root_abs = os.path.abspath(root_path)
    clean_rel = virtual_path.replace("\\", "/").lstrip("/")
    full_path = os.path.abspath(os.path.join(root_abs, clean_rel))
    if os.path.commonpath([root_abs, full_path]) != root_abs:
        raise PathTraversalSecurityError(
            f"Path escapes mount root: {full_path} (root: {root_abs})"
        )
    return full_path


def safe_read_bytes(
    root_path: str,
    virtual_path: str,
    max_bytes: int = 1_048_576,
) -> bytes | None:
    """Safely read binary content of a file within root_path up to max_bytes.

    Resolves in-image symlinks safely within root_path and enforces host-level
    containment so symlinks cannot escape the mount directory.

    Args:
        root_path: Local filesystem path representing root directory.
        virtual_path: Virtual path of the file to read.
        max_bytes: Maximum number of bytes to read.

    Returns:
        Bytes read from file, or None if file does not exist, is a directory,
        or cannot be accessed safely.
    """
    try:
        current_vpath = normalize_virtual_path(virtual_path)
        for _ in range(10):
            physical_path = safe_resolve_path(root_path, current_vpath)
            if os.path.islink(physical_path):
                resolved_vpath = safe_resolve_symlink(root_path, current_vpath)
                if resolved_vpath is None or resolved_vpath == current_vpath:
                    return None
                current_vpath = resolved_vpath
            else:
                break
        else:
            return None

        # Once resolved to a non-symlink file inside the image, ensure that any
        # parent directory symlink on the host didn't escape root_path.
        root_real = os.path.realpath(os.path.abspath(root_path))
        full_real = os.path.realpath(physical_path)
        if os.path.commonpath([root_real, full_real]) != root_real:
            return None
        if not os.path.isfile(full_real):
            return None
        with open(full_real, "rb") as f:
            return f.read(max_bytes)
    except (PathTraversalSecurityError, OSError):
        return None


def safe_read_text(
    root_path: str,
    virtual_path: str,
    max_bytes: int = 1_048_576,
    encoding: str = "utf-8",
    errors: str = "replace",
) -> str | None:
    """Safely read text content of a file within root_path up to max_bytes.

    Args:
        root_path: Local filesystem path representing root directory.
        virtual_path: Virtual path of the file to read.
        max_bytes: Maximum number of bytes to read.
        encoding: Text encoding to use.
        errors: Error handling scheme for decoding.

    Returns:
        Decoded text string, or None if file cannot be read safely.
    """
    data = safe_read_bytes(root_path, virtual_path, max_bytes=max_bytes)
    if data is None:
        return None
    return data.decode(encoding=encoding, errors=errors)


def _resolve_virtual_symlink_target(parent_vdir: str, target: str) -> str | None:
    """Resolve a symlink target path against a virtual parent directory.

    Args:
        parent_vdir: Normalized virtual directory containing the symlink.
        target: Symlink target string (relative or absolute).

    Returns:
        Normalized virtual path, or None if target attempts to traverse above root.
    """
    clean_target = target.replace("\\", "/")
    if clean_target.startswith("/"):
        parts = clean_target.split("/")
        stack: list[str] = []
    else:
        parts = clean_target.split("/")
        stack = [p for p in parent_vdir.split("/") if p]

    for part in parts:
        if not part or part == ".":
            continue
        if part == "..":
            if not stack:
                # Target attempts to traverse above root
                return None
            stack.pop()
        else:
            stack.append(part)

    return "/" + "/".join(stack)


def safe_resolve_symlink(root_path: str, virtual_path: str) -> str | None:
    """Safely resolve a symlink within root_path, returning the resolved virtual path.

    Args:
        root_path: Local filesystem path representing root directory.
        virtual_path: Virtual path of the symlink.

    Returns:
        Resolved virtual path, or None if virtual_path is not a symlink,
        target is invalid, or target escapes root_path.
    """
    try:
        physical_path = safe_resolve_path(root_path, virtual_path)
        if not os.path.islink(physical_path):
            return None

        target = os.readlink(physical_path)
        parent_vdir = posixpath.dirname(normalize_virtual_path(virtual_path))
        resolved_vpath = _resolve_virtual_symlink_target(parent_vdir, target)
        if resolved_vpath is None:
            return None

        # Validate that physical target doesn't escape root_path
        safe_resolve_path(root_path, resolved_vpath)
        return resolved_vpath
    except (PathTraversalSecurityError, OSError):
        return None


def _pattern_to_regex(pattern: str) -> re.Pattern[str]:
    """Convert a normalized virtual glob pattern to a compiled regex.

    Unlike naive fnmatch, '*' never matches path separators ('/').
    '**' matches zero or more directory segments.

    Args:
        pattern: Normalized virtual glob pattern.

    Returns:
        Compiled regex matching full paths.
    """
    norm = "/" + pattern.strip("/")
    parts = [p for p in norm.split("/") if p]
    pattern_re = "^"
    for part in parts:
        if part == "**":
            pattern_re += r"(?:/.*)?"
        else:
            rx = ""
            i = 0
            while i < len(part):
                c = part[i]
                if c == "*":
                    rx += r"[^/]*"
                    i += 1
                elif c == "?":
                    rx += r"[^/]"
                    i += 1
                elif c == "[":
                    j = part.find("]", i + 1)
                    if j != -1:
                        char_class = part[i + 1 : j]
                        if char_class.startswith("!"):
                            char_class = "^" + char_class[1:]
                        rx += "[" + char_class + "]"
                        i = j + 1
                    else:
                        rx += r"\["
                        i += 1
                elif c in r"\.+^$(){}|":
                    rx += "\\" + c
                    i += 1
                else:
                    rx += c
                    i += 1
            pattern_re += "/" + rx
    pattern_re += "$"
    return re.compile(pattern_re)


def _glob_literal_prefix(norm_pattern: str) -> str:
    """Return the literal directory prefix of a normalized glob pattern.

    The returned path (e.g. '/etc/systemd/system') is the longest directory
    prefix containing no glob metacharacters, allowing filesystem walks to be
    scoped to that subtree instead of scanning the entire target root.

    Args:
        norm_pattern: Normalized virtual glob pattern.

    Returns:
        Normalized virtual directory prefix with a leading slash.
    """
    meta_indices = [
        idx
        for idx in (
            norm_pattern.find("*"),
            norm_pattern.find("?"),
            norm_pattern.find("["),
        )
        if idx != -1
    ]
    first_meta = min(meta_indices) if meta_indices else len(norm_pattern)
    prefix = norm_pattern[:first_meta]
    prefix_dir = prefix.rsplit("/", 1)[0] if "/" in prefix else "/"
    return prefix_dir or "/"


@dataclass
class AnalysisTarget:
    """Unified abstraction for mounted disk images or extracted file collections."""

    root_path: str | None = None
    virtual_paths: dict[str, str] = field(default_factory=dict)
    source_file: dict[str, Any] | None = None
    is_mounted_image: bool = False

    def get_physical_path(self, virtual_path: str) -> str | None:
        """Resolve a virtual path to a physical filesystem path.

        Args:
            virtual_path: Virtual path of the target file.

        Returns:
            Physical filesystem path if it exists, or None.
        """
        norm_vpath = normalize_virtual_path(virtual_path)
        if norm_vpath in self.virtual_paths:
            phys = self.virtual_paths[norm_vpath]
            if os.path.exists(phys):
                return phys
        if self.root_path:
            try:
                phys = safe_resolve_path(self.root_path, norm_vpath)
                if os.path.exists(phys):
                    return phys
            except (PathTraversalSecurityError, OSError):
                return None
        return None

    def exists(self, virtual_path: str) -> bool:
        """Check if a virtual path exists.

        Args:
            virtual_path: Virtual path to check.

        Returns:
            True if the virtual path exists on filesystem or map, False otherwise.
        """
        return self.get_physical_path(virtual_path) is not None

    def read_bytes(self, virtual_path: str, max_bytes: int = 1_048_576) -> bytes | None:
        """Read bytes from a virtual path up to max_bytes.

        Args:
            virtual_path: Virtual path of the file to read.
            max_bytes: Maximum number of bytes to read.

        Returns:
            Bytes read from the file, or None if unreadable.
        """
        norm_vpath = normalize_virtual_path(virtual_path)
        if norm_vpath in self.virtual_paths:
            phys = self.virtual_paths[norm_vpath]
            try:
                if not os.path.isfile(phys):
                    return None
                with open(phys, "rb") as f:
                    return f.read(max_bytes)
            except OSError:
                return None
        if self.root_path:
            return safe_read_bytes(self.root_path, norm_vpath, max_bytes=max_bytes)
        return None

    def read_text(
        self,
        virtual_path: str,
        max_bytes: int = 1_048_576,
        encoding: str = "utf-8",
        errors: str = "replace",
    ) -> str | None:
        """Read text from a virtual path up to max_bytes.

        Args:
            virtual_path: Virtual path of the file to read.
            max_bytes: Maximum number of bytes to read.
            encoding: Text encoding to use.
            errors: Error handling scheme for decoding.

        Returns:
            Decoded text string, or None if unreadable.
        """
        data = self.read_bytes(virtual_path, max_bytes=max_bytes)
        if data is None:
            return None
        return data.decode(encoding=encoding, errors=errors)

    def glob(self, pattern: str) -> list[str]:
        """Find virtual paths matching a glob pattern.

        Args:
            pattern: Glob pattern (e.g. '/etc/systemd/system/*.service').

        Returns:
            Sorted list of matching normalized virtual paths.
        """
        matches: set[str] = set()
        norm_pattern = normalize_virtual_path(pattern)
        pattern_re = _pattern_to_regex(norm_pattern)

        # Match against mapped virtual paths
        for vpath in self.virtual_paths:
            if pattern_re.match(vpath):
                matches.add(vpath)

        # Match against filesystem tree under root_path if available. The walk
        # is scoped to the longest literal directory prefix of the pattern and
        # prunes directory descent beyond the pattern's depth.
        if self.root_path and os.path.isdir(self.root_path):
            root_abs = os.path.abspath(self.root_path)
            prefix_vdir = _glob_literal_prefix(norm_pattern)
            walk_root = os.path.abspath(os.path.join(root_abs, prefix_vdir.lstrip("/")))

            # Only walk when the scoped root is contained within the target
            # root once symlinks are resolved.
            root_real = os.path.realpath(root_abs)
            walk_real = os.path.realpath(walk_root)
            if (
                os.path.exists(walk_root)
                and os.path.commonpath([root_real, walk_real]) == root_real
            ):
                parts = [p for p in norm_pattern.split("/") if p]
                has_double_star = "**" in parts
                max_depth = len(parts) - 1 if not has_double_star else None

                for dirpath, dirnames, filenames in os.walk(
                    walk_root, followlinks=False
                ):
                    rel_dir = os.path.relpath(dirpath, root_abs)
                    rel_dir_parts = [p for p in rel_dir.split(os.sep) if p and p != "."]

                    # Prune recursion if current directory is at or beyond the
                    # maximum depth where matched files can reside.
                    if max_depth is not None and len(rel_dir_parts) >= max_depth:
                        dirnames.clear()

                    for fname in filenames:
                        full_phys = os.path.join(dirpath, fname)
                        rel = os.path.relpath(full_phys, root_abs)
                        vpath = normalize_virtual_path(rel)
                        if pattern_re.match(vpath):
                            matches.add(vpath)

        return sorted(matches)

    def resolve_symlink(self, virtual_path: str) -> str | None:
        """Safely resolve symlinks constrained to target root.

        Args:
            virtual_path: Virtual path of the symlink to resolve.

        Returns:
            Normalized virtual target path, or None if invalid or escapes root.
        """
        norm_vpath = normalize_virtual_path(virtual_path)
        if self.root_path:
            return safe_resolve_symlink(self.root_path, norm_vpath)
        if norm_vpath in self.virtual_paths:
            phys = self.virtual_paths[norm_vpath]
            try:
                if os.path.islink(phys):
                    target = os.readlink(phys)
                    parent_vdir = posixpath.dirname(norm_vpath)
                    return _resolve_virtual_symlink_target(parent_vdir, target)
            except OSError:
                return None
        return None


# Alias ArtifactTarget to AnalysisTarget for interchangeable naming across modules
ArtifactTarget = AnalysisTarget


@dataclass
class AnalysisContext:
    """Forensic context carrying analysis target, detected OS, and host information."""

    target: AnalysisTarget
    os_name: str = "linux"
    hostname: str = "unknown"


__all__ = [
    "AnalysisContext",
    "AnalysisTarget",
    "ArtifactTarget",
    "Finding",
    "PathTraversalSecurityError",
    "ReportMeta",
    "RiskLevel",
    "normalize_virtual_path",
    "safe_read_bytes",
    "safe_read_text",
    "safe_resolve_path",
    "safe_resolve_symlink",
]
