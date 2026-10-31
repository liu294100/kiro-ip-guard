from __future__ import annotations

import logging
import re
import threading
import time
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import Optional, TextIO

LOG_PREFIX = "kiro-ip-guard"
DEFAULT_RETENTION_DAYS = 7
DEFAULT_MAX_FILE_BYTES = 5 * 1024 * 1024
DEFAULT_MAX_TOTAL_BYTES = 30 * 1024 * 1024
_CLEANUP_INTERVAL_SECONDS = 10 * 60

# kiro-ip-guard-2026-10-31.log, kiro-ip-guard-2026-10-31-1.log
_DAILY_PATTERN = re.compile(rf"^{re.escape(LOG_PREFIX)}-(\d{{4}}-\d{{2}}-\d{{2}})(?:-(\d+))?\.log$")
# kiro-ip-guard.log, kiro-ip-guard.log.1 (written by v1.5.2 and earlier)
_LEGACY_PATTERN = re.compile(rf"^{re.escape(LOG_PREFIX)}\.log(?:\.\d+)?$")


class DailyLogHandler(logging.Handler):
    """Write one log file per day and delete old files automatically.

    Files are never renamed, so the tray process and the settings process can
    append to the same directory on Windows without rollover lock errors.
    """

    def __init__(
        self,
        directory: Path,
        retention_days: int = DEFAULT_RETENTION_DAYS,
        max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
        max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES,
    ) -> None:
        super().__init__()
        self.directory = Path(directory)
        self.retention_days = max(1, int(retention_days))
        self.max_file_bytes = max(64 * 1024, int(max_file_bytes))
        self.max_total_bytes = max(self.max_file_bytes, int(max_total_bytes))
        self._stream: Optional[TextIO] = None
        self._path: Optional[Path] = None
        self._day: Optional[date] = None
        self._next_cleanup = 0.0
        self._io_lock = threading.RLock()
        self.directory.mkdir(parents=True, exist_ok=True)
        self.cleanup()

    @property
    def current_path(self) -> Optional[Path]:
        return self._path

    def _path_for(self, day: date, index: int) -> Path:
        suffix = f"-{index}" if index else ""
        return self.directory / f"{LOG_PREFIX}-{day.isoformat()}{suffix}.log"

    def _open_for(self, day: date) -> None:
        self._close_stream()
        index = 0
        while True:
            path = self._path_for(day, index)
            try:
                size = path.stat().st_size
            except OSError:
                size = 0
            if size < self.max_file_bytes:
                break
            index += 1
        self._stream = path.open("a", encoding="utf-8")
        self._path = path
        self._day = day

    def _close_stream(self) -> None:
        if self._stream is not None:
            try:
                self._stream.close()
            except OSError:
                pass
        self._stream = None

    def emit(self, record: logging.LogRecord) -> None:
        try:
            message = self.format(record)
            with self._io_lock:
                today = datetime.fromtimestamp(record.created).date()
                if self._stream is None or today != self._day:
                    self._open_for(today)
                    self.cleanup()
                assert self._stream is not None
                self._stream.write(message + "\n")
                self._stream.flush()
                if self._stream.tell() >= self.max_file_bytes:
                    self._open_for(today)
                    self.cleanup()
                elif time.monotonic() >= self._next_cleanup:
                    self.cleanup()
        except Exception:
            self.handleError(record)

    def cleanup(self) -> None:
        """Delete logs older than the retention period, then cap total size."""
        self._next_cleanup = time.monotonic() + _CLEANUP_INTERVAL_SECONDS
        cutoff = date.today() - timedelta(days=self.retention_days - 1)
        kept: list[tuple[float, int, Path]] = []
        try:
            entries = list(self.directory.iterdir())
        except OSError:
            return
        for path in entries:
            name = path.name
            if _LEGACY_PATTERN.fullmatch(name):
                _remove_quietly(path)
                continue
            match = _DAILY_PATTERN.fullmatch(name)
            if not match:
                continue
            try:
                day = date.fromisoformat(match.group(1))
            except ValueError:
                continue
            if day < cutoff:
                _remove_quietly(path)
                continue
            try:
                stat = path.stat()
            except OSError:
                continue
            kept.append((stat.st_mtime, stat.st_size, path))

        total = sum(size for _, size, _ in kept)
        for _, size, path in sorted(kept):
            if total <= self.max_total_bytes:
                break
            if path == self._path:
                continue
            if _remove_quietly(path):
                total -= size

    def close(self) -> None:
        with self._io_lock:
            self._close_stream()
        super().close()


def _remove_quietly(path: Path) -> bool:
    try:
        path.unlink()
        return True
    except FileNotFoundError:
        return True
    except OSError:
        # Another process may still hold the file open on Windows; retry later.
        return False
