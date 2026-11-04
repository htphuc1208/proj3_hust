"""Bind a metadata snapshot without following files outside the declared target."""
from pathlib import Path

from research_core import digest
from .formats import sha


def metadata_inventory(target):
    root = Path(target).resolve(strict=True)
    paths = sorted(root.rglob("*.dist-info/METADATA"))
    # Validate all paths before hashing any bytes. In particular, a METADATA
    # symlink must not grant a collector access to another dataset or oracle.
    for path in paths:
        if path.is_symlink() or not path.resolve().is_relative_to(root) or any(
                parent.is_symlink() for parent in path.parents if parent != root and parent.is_relative_to(root)):
            raise ValueError("TARGET_METADATA_PATH_ESCAPES_SNAPSHOT_OR_IS_SYMLINK")
        if not path.is_file():
            raise ValueError("TARGET_METADATA_IS_NOT_A_REGULAR_FILE")
    return paths, sha([(str(p.relative_to(root)), digest(p)) for p in paths])
