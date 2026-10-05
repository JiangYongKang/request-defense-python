"""本地可查的防护判定历史（有界环形缓冲，线程安全）。

与结构化日志的区别：日志面向外部采集；本模块把最近 N 条判定保留在进程内存中，
通过 /__defense/decisions 即可本地复查"判定输入 -> 最终结论"，便于复现线上问题。
容量固定，写入 O(1)、内存有上界，绝不参与限流/拦截判定。
"""
from __future__ import annotations

from collections import deque
from threading import Lock
from typing import Any

#: 单次查询最多返回条数（防止一次响应过大），与容量无关的硬上界
HARD_FETCH_LIMIT = 1000


class DecisionHistory:
    """最近判定记录的有界环形缓冲。

    max_records <= 0 表示不保留（默认关闭，保持原有行为零开销）。
    """

    def __init__(self, max_records: int = 0) -> None:
        if max_records < 0:
            raise ValueError("max_records 必须 >= 0")
        self.max_records = max_records
        self._records: deque[dict[str, Any]] = deque(maxlen=max_records or None)
        self._lock = Lock()

    def add(self, record: dict[str, Any]) -> None:
        """追加一条判定记录（容量为 0 时直接丢弃）。"""
        if self.max_records == 0:
            return
        with self._lock:
            self._records.append(record)

    def recent(self, limit: int | None = None) -> list[dict[str, Any]]:
        """返回最近的判定记录（新的在前）。"""
        if limit is None or limit > HARD_FETCH_LIMIT:
            limit = HARD_FETCH_LIMIT
        if limit <= 0:
            return []
        with self._lock:
            if limit >= len(self._records):
                return list(reversed(self._records))
            # deque 不支持负切片，用迭代取尾部 limit 条
            tail = list(self._records)[-limit:]
            return list(reversed(tail))

    def __len__(self) -> int:
        with self._lock:
            return len(self._records)
