"""Detect writes to the production scan-history DB *from this test process*.

The previous guard compared the file's md5/size before and after each test.
That is racy: the long-running monitor legitimately writes the production DB
every poll, so any test whose window overlapped a poll failed at random
(e.g. test_absent_value_is_not_an_error). This guard instead intercepts
sqlite3.connect in-process and records any non-read-only open of the
production path, which is exactly what the tests mean to forbid.
"""
from __future__ import annotations

import os
import sqlite3
from pathlib import Path
from typing import List
from unittest import mock


def _target(database) -> str:
    s = os.fspath(database) if not isinstance(database, str) else database
    if s.startswith("file:"):
        s = s[5:].split("?", 1)[0]
    return s


class ProdDBWriteGuard:
    def __init__(self, production_db: Path) -> None:
        self.prod = Path(production_db).resolve()
        self.hits: List[str] = []
        self._real = sqlite3.connect
        self._patch = None

    def _connect(self, database, *args, **kwargs):
        raw = database if isinstance(database, str) else os.fspath(database)
        if raw != ":memory:":
            try:
                same = Path(_target(raw)).resolve() == self.prod
            except (OSError, ValueError):
                same = False
            read_only = "mode=ro" in raw or "immutable=1" in raw
            if same and not read_only:
                self.hits.append(raw)
        return self._real(database, *args, **kwargs)

    def start(self) -> "ProdDBWriteGuard":
        self._patch = mock.patch("sqlite3.connect", side_effect=self._connect)
        self._patch.start()
        return self

    def stop(self) -> List[str]:
        if self._patch is not None:
            self._patch.stop()
            self._patch = None
        return self.hits
