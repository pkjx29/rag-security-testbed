"""Document-level access control (defence D2).

Two layers, both fed by server-side data only:

1. Pre-filter: the principal's allowed access levels become a `where` filter
   inside the vector query, so restricted chunks are never scored or ranked.
2. Independent check: every chunk that comes back is checked again against the
   ACL written at ingestion time (data/processed/acl.json), a separate source
   from the metadata stored in Chroma. Unknown chunks and unknown roles are
   denied. A bug or tampering in the vector-store metadata therefore cannot, on
   its own, put unauthorised text in front of the model.

The principal comes from the application (API key lookup or the evaluation
harness). Nothing the user types ("I am the treating physician") is consulted.
"""
from __future__ import annotations

import json
from pathlib import Path

from ..config import ROLE_ACCESS
from ..schemas import Chunk, Principal


def allowed_levels(principal: Principal) -> frozenset[str]:
    return ROLE_ACCESS.get(principal.role, frozenset())        # deny by default


def where_filter(principal: Principal) -> dict:
    # An unknown role gets an impossible filter, which matches nothing.
    return {"access_level": {"$in": sorted(allowed_levels(principal)) or ["__none__"]}}


class AccessPolicy:
    def __init__(self, acl: dict[str, str]):
        self.acl = dict(acl)            # chunk_id -> access_level

    @classmethod
    def from_chunks(cls, chunks: list[Chunk]) -> AccessPolicy:
        return cls({c.chunk_id: str(c.metadata["access_level"]) for c in chunks})

    @classmethod
    def load(cls, path: Path) -> AccessPolicy:
        return cls(json.loads(path.read_text()))

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.acl, sort_keys=True))

    def register(self, chunk_id: str, access_level: str) -> None:
        """Used when a document is added after ingestion (the evaluation plants attack documents)."""
        self.acl[chunk_id] = access_level

    def unregister(self, chunk_id: str) -> None:
        self.acl.pop(chunk_id, None)

    def is_authorized(self, principal: Principal, chunk_id: str) -> bool:
        level = self.acl.get(chunk_id)
        return level is not None and level in allowed_levels(principal)

    def authorize(self, principal: Principal, chunks: list[Chunk]) -> tuple[list[Chunk], list[Chunk]]:
        kept = [c for c in chunks if self.is_authorized(principal, c.chunk_id)]
        denied = [c for c in chunks if not self.is_authorized(principal, c.chunk_id)]
        return kept, denied
