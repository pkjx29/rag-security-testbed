"""Retrieval-time access control (defence D2).

The user's role is resolved by the application (in a real system, from the
authenticated session), never from the question text. It becomes a metadata
filter inside the vector search itself, so restricted chunks are never scored,
ranked or placed in the prompt. Filtering *after* top-k retrieval would be weaker:
restricted chunks would still take up top-k slots, and the code path that drops
them becomes one more place for a bug.
"""
from .. import config


def where_filter(role: str) -> dict:
    allowed = config.ROLE_ACCESS[role]
    return {"access_level": {"$in": allowed}}
