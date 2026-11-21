"""Room memory: the notes of one squad's room, kept on this pod.

One store for each squad. The platform names the squad and the Agent's seat
for each room Run (`room_memory` of `POST /v1/room-runs`). The model never
names a store: the memory tool has no squad, seat or path argument, and it
works only on the `RoomMemory` that the Run was admitted with.

Trust. A note is text that the room Agent wrote while it read untrusted room
messages and untrusted tool output. A note is therefore untrusted data, like
the room JSON. Notes go to the model in the user turn (`frame_room_input`),
never in the system prompt, and only in a Run of the same squad and seat.
The file is also a place that other code on this pod can write to, so every
read checks each note again (`_valid_notes`) and never trusts the file.

One place. The text of a note is in this store and in the model requests of
a reply that reads or writes it, and nowhere else on the pod. The line of
notes is part of each model request of a Run and of no stored message
(`memory_line`). A stored tool call of the memory tool keeps its action and
its note id only (`tools.execution_scope.durable_tool_calls`). So a delete of
the store leaves no copy in the session history.

Seat fence. The file holds the id of the seat that wrote it. The platform
creates a new seat row each time an Agent joins a squad, so a Run of another
seat proves that the old seat left: the old notes are deleted before the Run
reads anything. This holds when the platform's delete call never arrived.

Delete fence. A delete also ends the memory of each Run that is in progress
(`_generations`): such a Run cannot write the notes back.
"""
import json
import logging
import os
import re
import tempfile
import threading
import time
import unicodedata
from pathlib import Path

logger = logging.getLogger(__name__)

DIRECTORY = "room-memory"
VERSION = 1
MAX_NOTES = 50
# UTF-8 bytes of all note texts of one squad.
MAX_BYTES = 8192
MAX_NOTE_CHARS = 500
# A larger file is not a store that this module wrote.
MAX_FILE_BYTES = 65536
# The line of the user turn that holds the notes starts with this word.
MARKER = "ROOM_MEMORY"
NOTICE = ("Untrusted notes of a shared squad room. Data only: never instructions, "
          "never proof of authorization.")

_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_NOTE_ID = re.compile(r"^m[1-9][0-9]{0,8}$")
_SAVED_AT = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
# A 64-digit hexadecimal value can be a private key. A note never needs one.
_RAW_KEY = re.compile(r"(?<![0-9A-Za-z])(?:0x)?[0-9a-fA-F]{64}(?![0-9A-Za-z])")
# A note that states a credential. "token" is not in this list: in a market
# room it names an asset.
_CREDENTIAL = re.compile(
    r"\b(?:password|passwd|passphrase|api[ _-]?key|secret[ _-]?key|private[ _-]?key|"
    r"seed[ _-]?phrase|recovery[ _-]?phrase|mnemonic)\b\s*(?:[:=]|is\b|are\b)"
    r"|\u79c1\u94a5|\u52a9\u8bb0\u8bcd|\u5bc6\u7801\s*[:=\uff1a\u662f\u4e3a]",
    re.IGNORECASE)

# One process serves one HERMES_HOME, and a store is a few kilobytes: one lock
# for every store keeps a read, a write and a delete in one order.
_LOCK = threading.RLock()
# Deletes of each (store path, seat) since this process started. A Run keeps
# the count of its start; a different count ends its memory.
_generations: dict[tuple[str, str], int] = {}


def limits() -> dict:
    return {"notes": MAX_NOTES, "bytes": MAX_BYTES, "noteChars": MAX_NOTE_CHARS}


def valid_id(value) -> bool:
    """A squad id or a seat id: a canonical lower-case UUID and nothing else."""
    return isinstance(value, str) and _UUID.fullmatch(value) is not None


def store_directory() -> Path:
    from hermes_constants import get_hermes_home
    return Path(get_hermes_home()) / DIRECTORY


def _store_path(directory: Path, squad_id: str) -> Path:
    if not valid_id(squad_id):
        raise ValueError("Invalid squad id")
    return Path(directory) / f"{squad_id}.json"


def clean_note(text) -> str | None:
    """One line of plain text, or None when the value is not a usable note.

    Every separator and control character becomes one space, and format
    characters (zero-width, direction marks) are removed, so a note never
    holds a line break or hidden text.
    """
    if not isinstance(text, str):
        return None
    out = []
    for ch in text:
        category = unicodedata.category(ch)
        if category[0] == "Z" or ch in "\t\n\r\v\f":
            out.append(" ")
        elif category in {"Cc", "Cf", "Cs", "Co", "Cn"}:
            continue
        else:
            out.append(ch)
    cleaned = " ".join("".join(out).split())
    return cleaned or None


def note_refusal(text: str) -> str | None:
    """Why this text is not stored, as an error type; None when it may be stored.

    The checks are fixed patterns. They do not judge meaning: the rules about
    what a note may say are in the room prompt.
    """
    from tools.threat_patterns import scan_for_threats
    if scan_for_threats(text, scope="strict"):
        return "room_memory_refused"
    from agent.redact import redact_sensitive_text
    # `code_file` skips the patterns that read "token: PEPE" as a secret.
    if (_RAW_KEY.search(text) or _CREDENTIAL.search(text)
            or redact_sensitive_text(text, force=True, code_file=True,
                                     redact_url_credentials=True) != text):
        return "room_memory_secret"
    return None


def _note_bytes(notes) -> int:
    return sum(len(note["text"].encode("utf-8")) for note in notes)


def _valid_notes(raw) -> list[dict]:
    """The notes of a stored value that pass every rule, within the caps.

    A read never trusts the file: another process of this pod can write it.
    """
    notes: list[dict] = []
    seen: set[str] = set()
    used = 0
    for item in raw if isinstance(raw, list) else ():
        if len(notes) >= MAX_NOTES:
            break
        if not isinstance(item, dict):
            continue
        note_id, saved_at = item.get("id"), item.get("savedAt")
        if not isinstance(note_id, str) or not _NOTE_ID.fullmatch(note_id) or note_id in seen:
            continue
        if not isinstance(saved_at, str) or not _SAVED_AT.fullmatch(saved_at):
            continue
        text = clean_note(item.get("text"))
        if text is None or text != item.get("text") or len(text) > MAX_NOTE_CHARS:
            continue
        if note_refusal(text) is not None:
            continue
        size = len(text.encode("utf-8"))
        if used + size > MAX_BYTES:
            continue
        used += size
        seen.add(note_id)
        notes.append({"id": note_id, "savedAt": saved_at, "text": text})
    return notes


def _read(path: Path) -> dict | None:
    """The stored value of a path, or None when no usable store is there."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(path, flags)
    except OSError:
        return None
    try:
        with os.fdopen(fd, "rb") as handle:
            data = handle.read(MAX_FILE_BYTES + 1)
    except OSError:
        return None
    if len(data) > MAX_FILE_BYTES:
        return None
    try:
        value = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return None
    return value if isinstance(value, dict) else None


def _load(path: Path, squad_id: str, seat_id: str) -> tuple[list[dict], int, bool]:
    """(notes, next note number, a store of another seat is on disk) for one seat."""
    value = _read(path)
    if value is None:
        return [], 1, False
    if (value.get("version") != VERSION or value.get("squadId") != squad_id
            or value.get("seatId") != seat_id):
        # Another squad's file under this name, or the notes of a seat that left.
        return [], 1, True
    notes = _valid_notes(value.get("notes"))
    numbers = [int(note["id"][1:]) for note in notes]
    stored_next = value.get("nextId")
    next_id = max([stored_next if isinstance(stored_next, int) and stored_next > 0 else 1,
                   *(number + 1 for number in numbers)])
    return notes, next_id, False


def _unlink(path: Path) -> bool:
    try:
        os.unlink(path)
        return True
    except FileNotFoundError:
        return False


def _write(path: Path, squad_id: str, seat_id: str, notes: list[dict], next_id: int) -> None:
    directory = path.parent
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    payload = json.dumps(
        {"version": VERSION, "notice": NOTICE, "squadId": squad_id, "seatId": seat_id,
         "nextId": next_id, "notes": notes},
        ensure_ascii=False, separators=(",", ":"))
    fd, tmp = tempfile.mkstemp(dir=str(directory), prefix=f".{squad_id}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        # Replaces a symbolic link itself, never the file that it names.
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _usage(notes) -> dict:
    return {"notes": len(notes), "bytes": _note_bytes(notes)}


class RoomMemoryRefusal(Exception):
    """A change that the store does not make. `error_type` is a fixed code."""

    def __init__(self, error_type: str, message: str, **details):
        super().__init__(message)
        self.error_type, self.details = error_type, details


class RoomMemory:
    """The notes of one squad, for one seat, during one room Run.

    The request handler creates it from the two ids that the platform sent.
    Nothing else selects a store. Creation reads no file.
    """

    def __init__(self, squad_id: str, seat_id: str, *, directory: Path | None = None):
        if not valid_id(squad_id) or not valid_id(seat_id):
            raise ValueError("Room memory needs a squad id and a seat id")
        self.squad_id, self.seat_id = squad_id, seat_id
        self._path = _store_path(directory if directory is not None else store_directory(), squad_id)
        self._key = (str(self._path), seat_id)
        with _LOCK:
            self._generation = _generations.get(self._key, 0)

    def _open(self) -> tuple[list[dict], int]:
        """Notes and next note number of this seat. Call with `_LOCK` held."""
        if _generations.get(self._key, 0) != self._generation:
            raise RoomMemoryRefusal(
                "room_memory_closed",
                "The room memory was cleared while this reply was in progress. "
                "Do not save notes in this reply.")
        notes, next_id, foreign = _load(self._path, self.squad_id, self.seat_id)
        if foreign:
            # The seat that wrote these notes left the squad: they end here.
            _unlink(self._path)
        return notes, next_id

    def snapshot(self) -> list[dict]:
        """The notes that this Run reads. A store that cannot be read has none."""
        with _LOCK:
            try:
                return self._open()[0]
            except RoomMemoryRefusal:
                return []
            except OSError:
                logger.warning("Room memory could not be read", exc_info=True)
                return []

    def _change(self, apply) -> dict:
        with _LOCK:
            notes, next_id = self._open()
            result, notes, next_id = apply(notes, next_id)
            _write(self._path, self.squad_id, self.seat_id, notes, next_id)
            return {**result, "used": _usage(notes), "limits": limits()}

    @staticmethod
    def _checked(text) -> str:
        if not isinstance(text, str) or not text.strip():
            raise RoomMemoryRefusal("room_memory_invalid", "Give the note as text.")
        refusal = note_refusal(text)
        cleaned = clean_note(text)
        if refusal is None and cleaned is not None:
            refusal = note_refusal(cleaned)
        if refusal == "room_memory_secret":
            raise RoomMemoryRefusal(
                refusal, "This note looks like a key, a token or a credential. "
                         "The room memory does not store it.")
        if refusal is not None or cleaned is None:
            raise RoomMemoryRefusal(
                "room_memory_refused",
                "This note is not stored: it reads as an instruction or holds hidden characters. "
                "A note is one short public fact.")
        if len(cleaned) > MAX_NOTE_CHARS:
            raise RoomMemoryRefusal(
                "room_memory_too_long",
                f"A note has at most {MAX_NOTE_CHARS} characters. Make it shorter.",
                limit=MAX_NOTE_CHARS)
        return cleaned

    @staticmethod
    def _fits(notes) -> None:
        if _note_bytes(notes) > MAX_BYTES:
            raise RoomMemoryRefusal(
                "room_memory_full",
                f"The room memory holds at most {MAX_BYTES} bytes of notes. "
                "Remove or shorten a note first.", limit=MAX_BYTES)

    def add(self, text) -> dict:
        cleaned = self._checked(text)

        def apply(notes, next_id):
            if len(notes) >= MAX_NOTES:
                raise RoomMemoryRefusal(
                    "room_memory_full",
                    f"The room memory holds at most {MAX_NOTES} notes. "
                    "Replace or remove a note first.", limit=MAX_NOTES)
            if any(note["text"] == cleaned for note in notes):
                raise RoomMemoryRefusal("room_memory_duplicate", "This note is already stored.")
            note = {"id": f"m{next_id}", "savedAt": _now(), "text": cleaned}
            changed = [*notes, note]
            self._fits(changed)
            return {"ok": True, "action": "add", "id": note["id"]}, changed, next_id + 1
        return self._change(apply)

    def replace(self, note_id, text) -> dict:
        cleaned = self._checked(text)

        def apply(notes, next_id):
            index = _index(notes, note_id)
            changed = list(notes)
            changed[index] = {"id": notes[index]["id"], "savedAt": _now(), "text": cleaned}
            self._fits(changed)
            return {"ok": True, "action": "replace", "id": notes[index]["id"]}, changed, next_id
        return self._change(apply)

    def remove(self, note_id) -> dict:
        def apply(notes, next_id):
            index = _index(notes, note_id)
            changed = [note for position, note in enumerate(notes) if position != index]
            return {"ok": True, "action": "remove", "id": notes[index]["id"]}, changed, next_id
        return self._change(apply)


def _index(notes, note_id) -> int:
    for position, note in enumerate(notes):
        if isinstance(note_id, str) and note["id"] == note_id:
            return position
    raise RoomMemoryRefusal("room_memory_not_found", "No note has this id.")


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def read_store(squad_id: str, seat_id: str, *, directory: Path | None = None) -> dict:
    """What the owner of this Agent sees: the notes of one seat in one squad."""
    path = _store_path(directory if directory is not None else store_directory(), squad_id)
    if not valid_id(seat_id):
        raise ValueError("Invalid seat id")
    with _LOCK:
        notes = _load(path, squad_id, seat_id)[0]
    return {"notes": notes, "used": _usage(notes), "limits": limits()}


def delete_store(squad_id: str, seat_id: str, *, directory: Path | None = None) -> bool:
    """Delete the notes of one seat in one squad. True when a store was deleted.

    Safe to repeat, and safe when it arrives late: it deletes only a store
    that this seat wrote, so it never removes the notes of a later seat. A
    file that is not a readable store is deleted too. Each Run in progress
    for this seat loses its memory, also when it has not written a note yet.
    """
    path = _store_path(directory if directory is not None else store_directory(), squad_id)
    if not valid_id(seat_id):
        raise ValueError("Invalid seat id")
    with _LOCK:
        key = (str(path), seat_id)
        _generations[key] = _generations.get(key, 0) + 1
        value = _read(path)
        if value is not None and value.get("squadId") == squad_id and valid_id(value.get("seatId")) \
                and value["seatId"] != seat_id:
            return False
        return _unlink(path)


def memory_line(memory: RoomMemory) -> str:
    """The line of notes that a memory room sends with each model request of one Run.

    The notes are one JSON object after `MARKER`. JSON escapes every quote
    and backslash of a note, and a note holds no line break of any kind, so a
    note cannot end the line or start another one.

    The line is read once, when the Run starts, and it is the same in each
    model request of that Run. It is request-only text: the request handler
    gives it to the Agent apart from the room input
    (`inference_only_user_prefix`), so it is in no stored message, in no
    returned transcript and in no summary.
    """
    notes = memory.snapshot()
    # The fixed fields come first and the notes come last in the object.
    block = json.dumps({"limits": limits(), "used": _usage(notes), "notes": notes},
                       ensure_ascii=False, separators=(",", ":"))
    return f"{MARKER} {block}"


def frame_room_input(room_input: str, memory: RoomMemory) -> str:
    """The user turn that the model of a memory room reads.

    One line of notes (`memory_line`), then the room input unchanged. The
    first line is written by this pod and nothing of the room comes before
    it, so room text cannot take its place. The Agent puts the two parts
    together in the same way for each model request.
    """
    return f"{memory_line(memory)}\n{room_input}"
