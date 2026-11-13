"""Local JSON state (stands in for the Hub database). Holds secrets: never commit it.

Several threads use it at once (page requests, the status poll, background watchers), so
every read, write and delete goes through one lock: a reader never sees a half-written file.
"""

import json
import pathlib
import re
import threading

STATE = pathlib.Path(__file__).resolve().parent.parent / "state"
_io = threading.Lock()


def slug(text):
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-") or "customer"


def _path(kind, name):
    return STATE / kind / f"{name}.json"


def load(kind, name):
    p = _path(kind, name)
    with _io:
        return json.loads(p.read_text(encoding="utf-8")) if p.exists() else None


def save(kind, name, record):
    p = _path(kind, name)
    data = json.dumps(record, indent=2)
    with _io:
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(data, encoding="utf-8")


def delete(kind, name):
    p = _path(kind, name)
    with _io:
        if p.exists():
            p.unlink()


def all_records(kind):
    d = STATE / kind
    with _io:
        return [json.loads(p.read_text(encoding="utf-8")) for p in sorted(d.glob("*.json"))] if d.exists() else []
