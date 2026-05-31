"""
GitSentinel File Scanner
High-performance file scanner with binary detection, parallel processing,
and hash-based caching for incremental scanning.
"""

import mmap
import os
import subprocess
import sys
from concurrent.futures import ProcessPoolExecutor, as_completed
from typing import Any, Dict, List, Optional, Set, Tuple

from gitsentinel.core.alerts import AlertManager, Finding
from gitsentinel.core.cache import FileHashCache, compute_file_hash
from gitsentinel.core.detector import SecretDetector, load_all_rules

# Magic bytes for common binary file formats
# If a file starts with any of these byte sequences, it is classified as binary
_BINARY_MAGIC_NUMBERS: List[bytes] = [
    b"\x89PNG",           # PNG image
    b"\xff\xd8\xff",      # JPEG image
    b"GIF87a",            # GIF87 image
    b"GIF89a",            # GIF89 image
    b"PK\x03\x04",        # ZIP archive / DOCX / XLSX / JAR
    b"PK\x05\x06",        # ZIP empty archive
    b"\x1f\x8b",          # GZIP
    b"BZ",                # BZIP2
    b"\x7fELF",           # ELF binary
    b"MZ",                # Windows PE executable
    b"\xca\xfe\xba\xbe",  # Mach-O binary (universal)
    b"\xfe\xed\xfa",      # Mach-O binary
    b"\x00\x00\x01\x00",  # ICO icon
    b"\x00\x00\x02\x00",  # CUR cursor
    b"RIFF",              # RIFF (WAV, AVI, WEBP)
    b"\x25\x50\x44\x46",  # PDF
    b"\xd0\xcf\x11\xe0",  # MS Office legacy (DOC, XLS, PPT)
    b"SQLite format",     # SQLite database
]

# File extensions known to be binary
_BINARY_EXTENSIONS: Set[str] = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".webp", ".svg",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".zip", ".tar", ".gz", ".bz2", ".7z", ".rar",
    ".exe", ".dll", ".so", ".dylib", ".bin", ".o", ".a",
    ".pyc", ".pyo", ".class", ".jar",
    ".mp3", ".mp4", ".avi", ".mov", ".mkv", ".flac", ".wav",
    ".ttf", ".otf", ".woff", ".woff2", ".eot",
    ".sqlite", ".db", ".lock",
}

# Maximum file size to scan (10MB)
_MAX_FILE_SIZE = 10 * 1024 * 1024

# Chunk size for reading files
_READ_CHUNK_SIZE = 65536


def is_binary_file(file_path: str) -> bool:
    """
    Quickly determine if a file is binary by checking magic numbers and extension.

    1. Check file extension against known binary extensions.
    2. Read the first 16 bytes and compare against magic number signatures.
    3. Check for null bytes in the first 8KB (fallback heuristic).

    Args:
        file_path: Path to the file to check.

    Returns:
        True if the file is likely binary, False if it's text.
    """
    # Extension check (fastest)
    _, ext = os.path.splitext(file_path)
    if ext.lower() in _BINARY_EXTENSIONS:
        return True

    # Magic number check
    try:
        with open(file_path, "rb") as fh:
            header = fh.read(16)
            if not header:
                return False

            for magic in _BINARY_MAGIC_NUMBERS:
                if header.startswith(magic):
                    return True

            # Null byte heuristic: read first 8KB
            fh.seek(0)
            sample = fh.read(8192)
            if b"\x00" in sample:
                return True

    except (OSError, PermissionError):
        return True  # Treat unreadable files as binary (skip them)

    return False


def read_file_content(file_path: str, max_size: int = _MAX_FILE_SIZE) -> Optional[str]:
    """
    Read file content safely with size limits.

    Args:
        file_path: Path to the file.
        max_size: Maximum file size to read in bytes.

    Returns:
        File content as string, or None if the file cannot be read.
    """
    try:
        file_size = os.path.getsize(file_path)
        if file_size > max_size:
            return None
        if file_size == 0:
            return ""

        with open(file_path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except (OSError, PermissionError, UnicodeDecodeError):
        return None


def get_staged_files() -> List[str]:
    """
    Get list of staged files from Git (added, copied, modified).

    Runs `git diff --cached --name-only --diff-filter=ACM` to get
    files staged for the next commit.

    Returns:
        List of file paths relative to the git repository root.
    """
    try:
        result = subprocess.run(
            ["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode != 0:
            return []

        files = [f.strip() for f in result.stdout.strip().split("\n") if f.strip()]
        return files
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return []


def get_all_tracked_files() -> List[str]:
    """
    Get all tracked files in the repository.

    Returns:
        List of tracked file paths.
    """
    try:
        result = subprocess.run(
            ["git", "ls-files"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode != 0:
            return []

        files = [f.strip() for f in result.stdout.strip().split("\n") if f.strip()]
        return files
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return []


def _load_ignore_patterns(repo_root: str) -> List[str]:
    """
    Load ignore patterns from .gitsentinelignore file.

    Each non-empty, non-comment line is treated as a glob pattern
    for files to skip during scanning.

    Args:
        repo_root: Root directory of the repository.

    Returns:
        List of glob pattern strings.
    """
    ignore_file = os.path.join(repo_root, ".gitsentinelignore")
    patterns: List[str] = []

    if not os.path.isfile(ignore_file):
        return patterns

    try:
        with open(ignore_file, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line and not line.startswith("#"):
                    patterns.append(line)
    except (OSError, PermissionError):
        pass

    return patterns


def _should_ignore_file(file_path: str, ignore_patterns: List[str]) -> bool:
    """
    Check if a file should be ignored based on ignore patterns.

    Supports simple glob-like matching:
    - Exact filename match
    - Extension match (e.g., *.log)
    - Directory prefix match (e.g., vendor/)

    Args:
        file_path: File path to check.
        ignore_patterns: List of ignore patterns.

    Returns:
        True if the file should be ignored.
    """
    import fnmatch

    basename = os.path.basename(file_path)
    for pattern in ignore_patterns:
        # Check against full path
        if fnmatch.fnmatch(file_path, pattern):
            return True
        # Check against basename
        if fnmatch.fnmatch(basename, pattern):
            return True
        # Check directory prefix
        if pattern.endswith("/") and file_path.startswith(pattern):
            return True

    return False


def _scan_single_file(
    file_path: str,
    entropy_enabled: bool = True,
    entropy_threshold: float = 4.5,
    hex_entropy_threshold: float = 3.0,
) -> List[Dict[str, Any]]:
    """
    Scan a single file for secrets. Designed to be called in a worker process.

    Args:
        file_path: Path to the file to scan.
        entropy_enabled: Whether to use entropy analysis.
        entropy_threshold: Entropy threshold for generic strings.
        hex_entropy_threshold: Entropy threshold for hex strings.

    Returns:
        List of finding dictionaries (serializable for cross-process transfer).
    """
    if is_binary_file(file_path):
        return []

    content = read_file_content(file_path)
    if content is None:
        return []

    detector = SecretDetector(
        entropy_enabled=entropy_enabled,
        entropy_threshold=entropy_threshold,
        hex_entropy_threshold=hex_entropy_threshold,
    )
    detector.add_rules(load_all_rules())

    findings = detector.scan_content(content, file_path)
    return [f.to_dict() for f in findings]


class FileScanner:
    """
    High-level file scanner that orchestrates parallel scanning with caching.

    Features:
    - Binary file detection and skipping
    - Hash-based caching for incremental scanning
    - Parallel file processing using ProcessPoolExecutor
    - Ignore pattern support via .gitsentinelignore
    """

    def __init__(
        self,
        cache_enabled: bool = True,
        cache_path: Optional[str] = None,
        max_workers: Optional[int] = None,
        entropy_enabled: bool = True,
        entropy_threshold: float = 4.5,
        hex_entropy_threshold: float = 3.0,
    ):
        """
        Initialize the file scanner.

        Args:
            cache_enabled: Whether to use file hash caching.
            cache_path: Path for the cache database.
            max_workers: Maximum number of parallel worker processes.
            entropy_enabled: Whether to run entropy analysis.
            entropy_threshold: Entropy threshold for generic strings.
            hex_entropy_threshold: Entropy threshold for hex strings.
        """
        self.cache_enabled = cache_enabled
        self.cache = FileHashCache(cache_path) if cache_enabled else None
        self.max_workers = max_workers or min(4, (os.cpu_count() or 1))
        self.entropy_enabled = entropy_enabled
        self.entropy_threshold = entropy_threshold
        self.hex_entropy_threshold = hex_entropy_threshold
        self.ignore_patterns: List[str] = []

    def load_ignore_patterns(self, repo_root: str) -> None:
        """Load ignore patterns from the repository root."""
        self.ignore_patterns = _load_ignore_patterns(repo_root)

    def scan_files(
        self, file_paths: List[str], parallel: bool = True
    ) -> AlertManager:
        """
        Scan a list of files for secrets.

        Args:
            file_paths: List of file paths to scan.
            parallel: Whether to use parallel processing.

        Returns:
            AlertManager containing all findings.
        """
        alert_manager = AlertManager()

        # Filter files
        files_to_scan = self._filter_files(file_paths)

        if not files_to_scan:
            return alert_manager

        # Sequential or parallel scanning
        if parallel and len(files_to_scan) > 1:
            findings = self._scan_parallel(files_to_scan)
        else:
            findings = self._scan_sequential(files_to_scan)

        alert_manager.add_findings(findings)

        # Update cache
        if self.cache_enabled and self.cache:
            for fp in files_to_scan:
                if os.path.isfile(fp):
                    file_hash = compute_file_hash(fp)
                    file_findings = len(
                        [f for f in findings if f.file_path == fp]
                    )
                    self.cache.update_cache(fp, file_hash, file_findings)

        return alert_manager

    def scan_staged(self) -> AlertManager:
        """
        Scan only staged files (for pre-commit hook integration).

        Returns:
            AlertManager containing findings from staged files.
        """
        staged_files = get_staged_files()
        return self.scan_files(staged_files)

    def scan_repository(self, repo_root: str) -> AlertManager:
        """
        Scan all tracked files in the repository.

        Args:
            repo_root: Root directory of the git repository.

        Returns:
            AlertManager containing all findings.
        """
        self.load_ignore_patterns(repo_root)
        tracked_files = get_all_tracked_files()
        # Convert to absolute paths
        abs_files = [
            os.path.join(repo_root, f) if not os.path.isabs(f) else f
            for f in tracked_files
        ]
        return self.scan_files(abs_files)

    def _filter_files(self, file_paths: List[str]) -> List[str]:
        """
        Filter files: skip binary, ignored, and cached (unchanged) files.

        Args:
            file_paths: List of file paths to filter.

        Returns:
            Filtered list of files that need scanning.
        """
        filtered: List[str] = []
        for fp in file_paths:
            if not os.path.isfile(fp):
                continue

            # Skip ignored files
            if _should_ignore_file(fp, self.ignore_patterns):
                continue

            # Skip binary files
            if is_binary_file(fp):
                continue

            # Skip unchanged files (cache check)
            if self.cache_enabled and self.cache and not self.cache.has_changed(fp):
                continue

            filtered.append(fp)

        return filtered

    def _scan_sequential(self, file_paths: List[str]) -> List[Finding]:
        """Scan files sequentially (used for small file sets)."""
        all_findings: List[Finding] = []
        detector = SecretDetector(
            entropy_enabled=self.entropy_enabled,
            entropy_threshold=self.entropy_threshold,
            hex_entropy_threshold=self.hex_entropy_threshold,
        )
        detector.add_rules(load_all_rules())

        for fp in file_paths:
            content = read_file_content(fp)
            if content is None:
                continue
            findings = detector.scan_content(content, fp)
            all_findings.extend(findings)

        return all_findings

    def _scan_parallel(self, file_paths: List[str]) -> List[Finding]:
        """
        Scan files in parallel using ProcessPoolExecutor.

        Each file is scanned in a separate process for true parallelism.
        Results are serialized as dicts and reconstructed as Finding objects.
        """
        all_findings: List[Finding] = []

        try:
            with ProcessPoolExecutor(max_workers=self.max_workers) as executor:
                future_to_file = {
                    executor.submit(
                        _scan_single_file,
                        fp,
                        self.entropy_enabled,
                        self.entropy_threshold,
                        self.hex_entropy_threshold,
                    ): fp
                    for fp in file_paths
                }

                for future in as_completed(future_to_file):
                    file_path = future_to_file[future]
                    try:
                        result_dicts = future.result(timeout=60)
                        for rd in result_dicts:
                            finding = Finding(
                                file_path=rd["file"],
                                line_number=rd["line"],
                                rule_id=rd["rule_id"],
                                description=rd["description"],
                                severity=rd["severity"],
                                matched_value=rd["matched_value"],
                                detection_method=rd["detection_method"],
                            )
                            all_findings.append(finding)
                    except Exception:
                        # If a worker fails, skip that file silently
                        pass
        except (OSError, RuntimeError):
            # Fallback to sequential if multiprocessing fails
            all_findings = self._scan_sequential(file_paths)

        return all_findings
