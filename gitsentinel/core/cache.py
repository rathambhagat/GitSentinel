"""
GitSentinel File Hash Cache
Lightweight SQLite-based cache to skip scanning of unmodified files.
Uses SHA-256 file hashes to detect changes.
"""

import hashlib
import json
import os
import sqlite3
import threading
from typing import Optional


# Read buffer size for hashing (64KB chunks for low memory footprint)
_HASH_CHUNK_SIZE = 65536


def compute_file_hash(file_path: str) -> str:
    """
    Compute SHA-256 hash of a file by reading in chunks.

    Uses 64KB chunks to maintain low memory footprint even for large files.

    Args:
        file_path: Absolute or relative path to the file.

    Returns:
        Hex digest of the file's SHA-256 hash.

    Raises:
        FileNotFoundError: If the file does not exist.
        PermissionError: If the file cannot be read.
    """
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as fh:
        while True:
            chunk = fh.read(_HASH_CHUNK_SIZE)
            if not chunk:
                break
            sha256.update(chunk)
    return sha256.hexdigest()


class FileHashCache:
    """
    SQLite-backed cache storing file hashes to enable incremental scanning.

    Only files whose hash has changed since the last scan will be re-scanned.
    Thread-safe via threading.Lock.
    """

    def __init__(self, cache_path: Optional[str] = None):
        """
        Initialize the file hash cache.

        Args:
            cache_path: Path to the SQLite database file.
                       Defaults to '.gitsentinel_cache.db' in current directory.
        """
        if cache_path is None:
            cache_path = os.path.join(os.getcwd(), ".gitsentinel_cache.db")
        self.cache_path = cache_path
        self._lock = threading.Lock()
        self._init_db()

    def _init_db(self) -> None:
        """Initialize the SQLite database and create the cache table if needed."""
        with self._lock:
            os.makedirs(os.path.dirname(self.cache_path) or ".", exist_ok=True)
            conn = sqlite3.connect(self.cache_path)
            try:
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS file_cache (
                        file_path TEXT PRIMARY KEY,
                        file_hash TEXT NOT NULL,
                        last_scanned TEXT NOT NULL,
                        findings_count INTEGER DEFAULT 0
                    )
                    """
                )
                conn.commit()
            finally:
                conn.close()

    def get_cached_hash(self, file_path: str) -> Optional[str]:
        """
        Retrieve the cached hash for a file.

        Args:
            file_path: Path to the file (will be normalized).

        Returns:
            Cached hash string, or None if not in cache.
        """
        normalized = os.path.normpath(os.path.abspath(file_path))
        with self._lock:
            conn = sqlite3.connect(self.cache_path)
            try:
                cursor = conn.execute(
                    "SELECT file_hash FROM file_cache WHERE file_path = ?",
                    (normalized,),
                )
                row = cursor.fetchone()
                return row[0] if row else None
            finally:
                conn.close()

    def update_cache(
        self, file_path: str, file_hash: str, findings_count: int = 0
    ) -> None:
        """
        Update or insert the hash for a file in the cache.

        Args:
            file_path: Path to the file (will be normalized).
            file_hash: SHA-256 hex digest of the file.
            findings_count: Number of findings from the last scan.
        """
        normalized = os.path.normpath(os.path.abspath(file_path))
        from datetime import datetime, timezone

        timestamp = datetime.now(timezone.utc).isoformat()
        with self._lock:
            conn = sqlite3.connect(self.cache_path)
            try:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO file_cache
                        (file_path, file_hash, last_scanned, findings_count)
                    VALUES (?, ?, ?, ?)
                    """,
                    (normalized, file_hash, timestamp, findings_count),
                )
                conn.commit()
            finally:
                conn.close()

    def has_changed(self, file_path: str) -> bool:
        """
        Check if a file has changed since last scan.

        Computes current hash and compares against cached hash.

        Args:
            file_path: Path to the file.

        Returns:
            True if the file has changed or is not in cache.
        """
        if not os.path.isfile(file_path):
            return True

        current_hash = compute_file_hash(file_path)
        cached_hash = self.get_cached_hash(file_path)
        return current_hash != cached_hash

    def remove_entry(self, file_path: str) -> None:
        """Remove a file entry from the cache."""
        normalized = os.path.normpath(os.path.abspath(file_path))
        with self._lock:
            conn = sqlite3.connect(self.cache_path)
            try:
                conn.execute(
                    "DELETE FROM file_cache WHERE file_path = ?", (normalized,)
                )
                conn.commit()
            finally:
                conn.close()

    def clear(self) -> None:
        """Clear all cache entries."""
        with self._lock:
            conn = sqlite3.connect(self.cache_path)
            try:
                conn.execute("DELETE FROM file_cache")
                conn.commit()
            finally:
                conn.close()

    def get_stats(self) -> dict:
        """Get cache statistics."""
        with self._lock:
            conn = sqlite3.connect(self.cache_path)
            try:
                cursor = conn.execute("SELECT COUNT(*) FROM file_cache")
                total = cursor.fetchone()[0]
                cursor = conn.execute(
                    "SELECT SUM(findings_count) FROM file_cache"
                )
                row = cursor.fetchone()
                total_findings = row[0] if row[0] is not None else 0
                return {"cached_files": total, "total_findings": total_findings}
            finally:
                conn.close()
