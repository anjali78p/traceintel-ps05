from __future__ import annotations
import json
import sqlite3
from datetime import datetime


class Cache:
    """SQLite response cache so demos/investigations keep working offline and results stay reproducible."""

    def __init__(self, path=":memory:"):
        self.db = sqlite3.connect(path)
        self.db.execute("CREATE TABLE IF NOT EXISTS cache(key TEXT PRIMARY KEY, retrieved_at TEXT, data TEXT)")

    def get(self, key):
        r = self.db.execute("SELECT retrieved_at, data FROM cache WHERE key=?", (key,)).fetchone()
        return (datetime.fromisoformat(r[0]), json.loads(r[1])) if r else None

    def put(self, key, when: datetime, data):
        self.db.execute("INSERT OR REPLACE INTO cache VALUES(?,?,?)", (key, when.isoformat(), json.dumps(data)))
        self.db.commit()
