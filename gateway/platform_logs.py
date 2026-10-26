"""Fixed gateway log source for authenticated hosted control planes."""
import os
import stat
from pathlib import Path


def read_gateway_log(home: Path, body: dict) -> dict:
    """Bound memory and retain incomplete lines; cursors bind the open inode."""
    if not isinstance(body, dict) or set(body) - {"limit", "maxBytes", "cursor"}:
        raise ValueError("Invalid log operation")
    limit, cap, cursor = body.get("limit", 5000), body.get("maxBytes", 1_000_000), body.get("cursor")
    if type(limit) is not int or not 1 <= limit <= 5000 or type(cap) is not int or not 1 <= cap <= 1_000_000:
        raise ValueError("Invalid log bounds")
    if cursor is not None and (not isinstance(cursor, dict) or set(cursor) != {"dev", "ino", "offset"}
            or any(type(value) is not int or not 0 <= value < 2**63 for value in cursor.values())):
        raise ValueError("Invalid log cursor")
    try:
        directory = os.open(home / "logs", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except FileNotFoundError:
        return {"lines": [], "cursor": {"dev": 0, "ino": 0, "offset": 0}}
    try:
        try:
            fd = os.open("gateway.log", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        except FileNotFoundError:
            return {"lines": [], "cursor": {"dev": 0, "ino": 0, "offset": 0}}
    finally:
        os.close(directory)
    with os.fdopen(fd, "rb") as source:
        info = os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode):
            raise OSError("Log source is not regular")
        initial = cursor is None
        same_file = cursor and cursor["dev"] == info.st_dev and cursor["ino"] == info.st_ino
        start = max(0, info.st_size - cap) if initial else (
            cursor["offset"] if same_file and cursor["offset"] <= info.st_size else 0)
        skip_partial_line = False
        if initial and start > 0:
            # The first line is complete when the bounded window starts just
            # after a newline. Probe its preceding byte before discarding it.
            source.seek(start - 1)
            skip_partial_line = source.read(1) != b"\n"
        source.seek(start)
        data = source.read(cap)
        complete = data.rfind(b"\n") + 1
        # A line exceeding the read cap cannot stall following forever.
        consumed = complete or (len(data) if len(data) == cap else 0)
        lines = data[:complete].split(b"\n")[:-1]
        if skip_partial_line:
            lines = lines[1:]
        if initial:
            lines = lines[-limit:]
        elif len(lines) > limit:
            lines = lines[:limit]
            consumed = sum(len(line) + 1 for line in lines)
        return {"lines": [line.decode("utf-8", errors="replace") for line in lines],
                "cursor": {"dev": info.st_dev, "ino": info.st_ino, "offset": start + consumed}}
