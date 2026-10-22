"""Output filter (defence D4): applied to the model's answer before the caller sees it.

Checks, in order:
  1. system secret: the deployment canary, also in transformed forms (case,
     spacing or punctuation changed, e.g. "nw assist 7731");
  2. links: markdown images and URLs whose domain is not on the allowlist (blocks
     zero-click exfiltration through image URLs, and phishing links);
  3. personal data: Presidio, with the same recognizers as index-time redaction.

Policy "redact" removes what was found and returns the rest; policy "block"
replaces the whole answer with a refusal if anything was found. A leaked secret
always blocks. Actions name the check and the entity type, never the value.

What this cannot catch: an injected instruction that changes what the answer
says (goal hijacking, false claims) without links, secrets or personal data.
"""
from __future__ import annotations

import re
from urllib.parse import urlparse

from ..config import SYSTEM_CANARY, URL_ALLOWLIST
from ..privacy.redaction import ENTITIES, redact_with_stats

MD_IMAGE = re.compile(r"!\[[^\]]*\]\([^)]*\)")
MD_LINK = re.compile(r"\[([^\]]*)\]\((https?://[^)\s]+)[^)]*\)")
BARE_URL = re.compile(r"https?://[^\s)\]>\"']+")
WITHHELD = "[response withheld by the output filter]"
_ALNUM = re.compile(r"[^a-z0-9]")


def _squash(s: str) -> str:
    return _ALNUM.sub("", s.lower())


def contains_canary(text: str, canary: str = SYSTEM_CANARY) -> bool:
    return _squash(canary) in _squash(text)


def url_allowed(url: str) -> bool:
    host = (urlparse(url).hostname or "").lower()
    return any(host == d or host.endswith("." + d) for d in URL_ALLOWLIST)


def filter_output(text: str, policy: str = "redact") -> tuple[str, list[str]]:
    """Return (text to show, actions taken)."""
    if contains_canary(text):
        return WITHHELD, ["withheld:system_secret"]
    actions: list[str] = []

    def drop_image(m: re.Match) -> str:
        actions.append("removed_image")
        return "[image removed]"

    def fix_link(m: re.Match) -> str:
        if url_allowed(m.group(2)):
            return m.group(0)
        actions.append("removed_link")
        return m.group(1)

    def drop_url(m: re.Match) -> str:
        if url_allowed(m.group(0)):
            return m.group(0)
        actions.append("removed_url")
        return "[link removed]"

    out = MD_IMAGE.sub(drop_image, text)
    out = MD_LINK.sub(fix_link, out)
    out = BARE_URL.sub(drop_url, out)
    out, counts = redact_with_stats(out)
    # DATE_TIME alone is too common in normal guidance ("published in 2024") to count as a finding.
    actions += [f"redacted:{e}" for e in ENTITIES if counts.get(e) and e != "DATE_TIME"]
    if policy == "block" and actions:
        return WITHHELD, actions + ["withheld:policy_block"]
    return out, actions
