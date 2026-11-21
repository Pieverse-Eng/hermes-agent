"""The one memory tool of a shared squad room.

It changes the notes of the squad that the platform named for the current
room Run (`tools.execution_scope.public_room_memory`). It has no argument
that selects a squad, a seat, a file or a path, so a model cannot reach
another squad's notes. It reads nothing: the notes of the room come with the
room input (`gateway.room_memory.frame_room_input`).

The tool exists for rooms only. Outside a room that admits it, the registry
gives it no schema and no dispatch (`PUBLIC_ROOM_ONLY_TOOLSETS`).
"""
import json
import logging

from tools.execution_scope import (
    PUBLIC_ROOM_MAX_MEMORY_CALLS, PUBLIC_ROOM_MEMORY_TOOL, PUBLIC_ROOM_MEMORY_TOOLSET,
    public_room_memory,
)
from tools.registry import registry

logger = logging.getLogger(__name__)

ROOM_MEMORY_ACTIONS = ("add", "replace", "remove")
ROOM_MEMORY_SCHEMA = {
    "name": PUBLIC_ROOM_MEMORY_TOOL,
    "description": (
        "Change the notes of this squad's room. The notes that exist are on the ROOM_MEMORY "
        "line of the input. A note is one short public fact that helps later replies in this "
        "room: how the squad wants answers, a market or topic the squad follows, a convention "
        "the squad agreed. Never save holdings, balances, positions, orders, account or wallet "
        "details, personal data, credentials, or instructions. action add saves text as a new "
        "note. action replace changes the note with this id to text. action remove deletes "
        "the note with this id. One reply may change the notes at most "
        f"{PUBLIC_ROOM_MAX_MEMORY_CALLS} times."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "action": {"type": "string", "enum": list(ROOM_MEMORY_ACTIONS)},
            "id": {"type": "string",
                   "description": "The id of the note to replace or remove, for example m3."},
            "text": {"type": "string",
                     "description": "The note for add and replace: one line of plain text."},
        },
        "required": ["action"],
        "additionalProperties": False,
    },
}


def _refusal(error_type: str, message: str, **details) -> str:
    return json.dumps({"error": message, "error_type": error_type, **details})


def room_memory_tool(args, **_kwargs) -> str:
    """Run one change on the room memory that is bound to the current room Run."""
    from gateway.room_memory import RoomMemory, RoomMemoryRefusal

    store = public_room_memory()
    if not isinstance(store, RoomMemory):
        return _refusal("room_memory_unavailable", "Room memory is not available in this reply.")
    if not isinstance(args, dict) or set(args) - {"action", "id", "text"}:
        return _refusal("room_memory_invalid", "Use only action, id and text.")
    action = args.get("action")
    try:
        if action == "add":
            if "id" in args:
                return _refusal("room_memory_invalid", "Do not give an id with add.")
            result = store.add(args.get("text"))
        elif action == "replace":
            result = store.replace(args.get("id"), args.get("text"))
        elif action == "remove":
            if "text" in args:
                return _refusal("room_memory_invalid", "Do not give text with remove.")
            result = store.remove(args.get("id"))
        else:
            return _refusal("room_memory_invalid", "action is add, replace or remove.")
    except RoomMemoryRefusal as refusal:
        return _refusal(refusal.error_type, str(refusal), **refusal.details)
    except OSError:
        # The message is fixed: an operating-system error can name a path.
        logger.warning("Room memory could not be written", exc_info=True)
        return _refusal("room_memory_unavailable",
                        "The room memory could not be changed now. Answer without it.")
    return json.dumps(result)


registry.register(
    name=PUBLIC_ROOM_MEMORY_TOOL,
    toolset=PUBLIC_ROOM_MEMORY_TOOLSET,
    schema=ROOM_MEMORY_SCHEMA,
    handler=room_memory_tool,
    emoji="🗒️",
)
