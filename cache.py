"""File-based cache with a 24-hour TTL."""

import hashlib
import json
import time
from pathlib import Path

CACHE_DIR = Path(".cache")
TTL = 24 * 60 * 60  # seconds


def _path(service: str, key: str) -> Path:
    h = hashlib.md5(f"{service}:{key}".encode()).hexdigest()
    return CACHE_DIR / f"{h}.json"


def get(service: str, key: str):
    CACHE_DIR.mkdir(exist_ok=True)
    p = _path(service, key)
    if not p.exists():
        return None
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        if time.time() - data["_at"] > TTL:
            p.unlink(missing_ok=True)
            return None
        return data["v"]
    except (json.JSONDecodeError, KeyError):
        return None


def put(service: str, key: str, payload) -> None:
    CACHE_DIR.mkdir(exist_ok=True)
    _path(service, key).write_text(
        json.dumps({"_at": time.time(), "v": payload}), encoding="utf-8"
    )
