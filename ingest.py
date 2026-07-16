"""
Safe ingestion of uploaded logs: individual files or archives.

Guards against zip-slip / path traversal and enforces extraction caps.
"""

from __future__ import annotations

import os
import tarfile
import zipfile
from typing import List

# Caps applied during archive extraction to resist decompression bombs.
MAX_EXTRACTED_BYTES = 512 * 1024 * 1024   # 512 MB total extracted
MAX_ENTRIES = 5000                        # max files per archive

ARCHIVE_EXTS = (".tar", ".tar.gz", ".tgz", ".zip")


class IngestError(Exception):
    """Raised for unsupported / unsafe / corrupt uploads."""


def is_archive(filename: str) -> bool:
    lower = filename.lower()
    return lower.endswith(ARCHIVE_EXTS)


def _safe_join(base: str, *paths: str) -> str:
    """Join and verify the resolved path stays within ``base``."""
    target = os.path.realpath(os.path.join(base, *paths))
    base_real = os.path.realpath(base)
    if target != base_real and not target.startswith(base_real + os.sep):
        raise IngestError(f"Unsafe path in archive: {os.path.join(*paths)!r}")
    return target


def _rel_name(root: str, path: str) -> str:
    return os.path.relpath(path, root).replace(os.sep, "/")


def extract_archive(archive_path: str, dest_dir: str) -> List[str]:
    """Extract a supported archive into ``dest_dir`` safely.

    Returns the list of absolute paths of extracted regular files.
    """
    lower = archive_path.lower()
    if lower.endswith(".zip"):
        return _extract_zip(archive_path, dest_dir)
    if lower.endswith((".tar", ".tar.gz", ".tgz")):
        return _extract_tar(archive_path, dest_dir)
    raise IngestError(f"Unsupported archive type: {archive_path}")


def _extract_zip(archive_path: str, dest_dir: str) -> List[str]:
    extracted: List[str] = []
    total = 0
    try:
        with zipfile.ZipFile(archive_path) as zf:
            infos = zf.infolist()
            if len(infos) > MAX_ENTRIES:
                raise IngestError("Archive has too many entries")
            for info in infos:
                if info.is_dir():
                    continue
                target = _safe_join(dest_dir, info.filename)
                total += info.file_size
                if total > MAX_EXTRACTED_BYTES:
                    raise IngestError("Archive exceeds extraction size limit")
                os.makedirs(os.path.dirname(target), exist_ok=True)
                with zf.open(info) as src, open(target, "wb") as dst:
                    dst.write(src.read())
                extracted.append(target)
    except zipfile.BadZipFile as exc:
        raise IngestError("Corrupt or invalid zip archive") from exc
    return extracted


def _extract_tar(archive_path: str, dest_dir: str) -> List[str]:
    extracted: List[str] = []
    total = 0
    try:
        with tarfile.open(archive_path, "r:*") as tf:
            members = tf.getmembers()
            if len(members) > MAX_ENTRIES:
                raise IngestError("Archive has too many entries")
            for member in members:
                if not member.isfile():
                    continue
                target = _safe_join(dest_dir, member.name)
                total += member.size
                if total > MAX_EXTRACTED_BYTES:
                    raise IngestError("Archive exceeds extraction size limit")
                os.makedirs(os.path.dirname(target), exist_ok=True)
                src = tf.extractfile(member)
                if src is None:
                    continue
                with open(target, "wb") as dst:
                    dst.write(src.read())
                extracted.append(target)
    except tarfile.TarError as exc:
        raise IngestError("Corrupt or invalid tar archive") from exc
    return extracted


def collect_log_files(root: str) -> List[str]:
    """Return all regular files under ``root`` (recursively), sorted by name."""
    found: List[str] = []
    for dirpath, _dirs, files in os.walk(root):
        for name in files:
            found.append(os.path.join(dirpath, name))
    found.sort(key=lambda p: _rel_name(root, p).lower())
    return found
