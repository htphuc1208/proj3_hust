"""Atomic artifact writes, including durability across an interrupted host session."""
import hashlib
import json
import os
from pathlib import Path
import tempfile


def save(path, value):
    data = json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False,
                      default=lambda v: sorted(v) if isinstance(v, set) else str(v)) + "\n"
    save_bytes(path, data.encode("utf-8"))


def save_bytes(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix="." + path.name + ".", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def quarantine(path):
    """Retain an incomplete newly generated artifact instead of replacing its evidence silently."""
    path = Path(path)
    raw = path.read_bytes()
    folder = path.parent / "interrupted-artifacts"
    folder.mkdir(exist_ok=True)
    destination = folder / (path.name + "." + hashlib.sha256(raw).hexdigest()[:16] + ".incomplete")
    if destination.exists():
        if destination.read_bytes() != raw:
            raise ValueError("Quarantine digest collision")
        # A duplicate is still preserved; use a unique suffix for the second occurrence.
        descriptor, duplicate = tempfile.mkstemp(prefix=destination.name + ".", dir=folder)
        os.close(descriptor)
        destination = Path(duplicate)
    os.replace(path, destination)
    return str(destination)
