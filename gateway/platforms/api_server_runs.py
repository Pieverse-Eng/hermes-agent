"""Bounded native run event fanout, selectively backported from NousResearch.

See docs/development/agent-chat-backport.md for upstream provenance.
"""
import asyncio
from collections import deque
from typing import Any, Dict, Optional

_RUN_STREAM_SUBSCRIBER_OVERFLOW = object()
_RUN_STREAM_WRITE_TIMEOUT = 5.0


class _RunStream:
    """Sequence and retain one run's events while fanning out to SSE clients."""

    BACKLOG_LIMIT = 1000
    SUBSCRIBER_QUEUE_LIMIT = 256

    def __init__(self) -> None:
        self.subscribers: set[asyncio.Queue] = set()
        self.backlog: deque[tuple[int, Optional[Dict[str, Any]]]] = deque(
            maxlen=self.BACKLOG_LIMIT
        )
        self.next_seq = 0
        self.terminal = False

    def put_nowait(self, event: Optional[Dict[str, Any]]) -> None:
        if self.terminal:
            return
        seq = self.next_seq
        self.next_seq += 1
        self.backlog.append((seq, event))
        if event is None:
            self.terminal = True
        for queue in list(self.subscribers):
            try:
                queue.put_nowait((seq, event))
            except asyncio.QueueFull:
                self.detach(queue)
                while not queue.empty():
                    queue.get_nowait()
                queue.put_nowait((seq, _RUN_STREAM_SUBSCRIBER_OVERFLOW))

    def attach(
        self, last_seq: int = -1
    ) -> tuple[asyncio.Queue, list[tuple[int, Optional[Dict[str, Any]]]]]:
        replay = [(seq, event) for seq, event in self.backlog if seq > last_seq]
        # Headroom for events produced while the replay is still being written.
        queue: asyncio.Queue = asyncio.Queue(maxsize=self.SUBSCRIBER_QUEUE_LIMIT + len(replay))
        self.subscribers.add(queue)
        return queue, replay

    def detach(self, queue: asyncio.Queue) -> None:
        self.subscribers.discard(queue)
