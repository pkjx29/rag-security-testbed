"""Output filtering (defence D3): applied to the model's answer before the user sees it.

Three independent checks:
  1. system-prompt leak: if the answer contains the secret deployment tag, the
     whole answer is withheld (canary-token approach used by tools such as Rebuff);
  2. links: markdown images and URLs whose domain is not on the allowlist are
     removed. This blocks zero-click exfiltration (an image URL the client would
     fetch automatically) and phishing links;
  3. personal data: the answer goes through the same Presidio redactor used at
     index time.

What this does NOT catch: an injected instruction that changes what the answer
says (goal hijacking, false claims) without links, secrets or personal data.
"""
import re
from urllib.parse import urlparse

from .. import config
from .redaction import redact

MD_IMAGE = re.compile(r"!\[[^\]]*\]\([^)]*\)")
MD_LINK = re.compile(r"\[([^\]]*)\]\((https?://[^)\s]+)[^)]*\)")
BARE_URL = re.compile(r"https?://[^\s)\]>\"']+")
WITHHELD = "[response withheld: it contained confidential system configuration]"


def _allowed(url: str) -> bool:
    host = (urlparse(url).hostname or "").lower()
    return any(host == d or host.endswith("." + d) for d in config.URL_ALLOWLIST)


def filter_output(text: str) -> tuple[str, list[str]]:
    """Return (filtered_text, list of actions taken)."""
    actions = []
    if config.SYSTEM_CANARY.lower() in text.lower():
        return WITHHELD, ["withheld_system_secret"]

    def drop_image(m):
        actions.append("removed_image")
        return "[image removed]"
    text = MD_IMAGE.sub(drop_image, text)

    def fix_link(m):
        if _allowed(m.group(2)):
            return m.group(0)
        actions.append("removed_link")
        return m.group(1)
    text = MD_LINK.sub(fix_link, text)

    def drop_url(m):
        if _allowed(m.group(0)):
            return m.group(0)
        actions.append("removed_url")
        return "[link removed]"
    text = BARE_URL.sub(drop_url, text)

    redacted = redact(text)
    if redacted != text:
        actions.append("redacted_pii")
    return redacted, actions
