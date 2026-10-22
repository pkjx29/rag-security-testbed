"""Injection filter (defence D3) for indirect prompt injection in retrieved text.

A deterministic regex scanner flags retrieved chunks that look like instructions
aimed at an AI system, and gives a readable reason for each flag. The pipeline then
applies the configured policy:
  exclude - drop flagged chunks; answer from the rest (default)
  block   - refuse the whole request if any retrieved chunk is flagged
Detection is kept separate from retrieval: this module only sees chunks.

Caveat, stated in the README: the same person wrote these rules and the attack
suite. The rules target phrasings common in publicly documented prompt-
injection examples and were not tuned per test case, but this is still the
most favourable setting a rule-based filter will get. The per-carrier breakdown in
results shows which phrasing styles get past it.
"""
from __future__ import annotations

import re
import unicodedata

from ..schemas import Chunk

ZERO_WIDTH = dict.fromkeys(map(ord, "​‌‍⁠﻿"), None)

RULES = {
    "ignore_previous": r"\b(ignore|disregard|forget|override)\b.{0,40}\b(previous|prior|above|earlier|all|any|your)\b.{0,20}\b(instructions?|directions?|rules|guidelines|context|prompt)",
    "fake_role_tag": r"(\[|<\|?|\{)\s*(system|admin|assistant|developer)\s*(\]|\|?>|\}|:)|^\s*(system|admin)\s*:",
    "addressed_to_ai": r"\b(note|message|instructions?|attention)\b.{0,15}\b(to|for)\b.{0,10}\b(ai|assistants?|language models?|llms?|chatbots?|bots?)\b",
    "persona_switch": r"\byou are now\b|\bact as\b|\bpretend (to be|you are)\b|\bnew instructions\b|\bdeveloper mode\b",
    "forced_output": r"\b(respond|reply|answer|output)\b.{0,20}\b(only|exactly|verbatim)\b",
    "prompt_extraction": r"\b(print|reveal|repeat|show|output|disclose)\b.{0,30}\b(system|initial|hidden|original)\b.{0,15}\b(prompt|instructions|message|configuration)",
    "markdown_image": r"!\[[^\]]*\]\(\s*https?://",
    "credential_request": r"\b(enter|provide|confirm|re-?enter|verify)\b.{0,40}\b(password|credentials|username and password|login)\b",
    "hidden_comment": r"<!--.*?-->",
    # Added with the pipeline restructure, before the indirect-extraction cases were written:
    "permission_change": r"\b(grant|elevate|escalate|upgrade|assign)\b.{0,30}\b(admin(istrator)?|privileges?|permissions?|access level|role)\b",
    "data_exfiltration": r"\b(include|append|list|send|forward|attach)\b.{0,40}\b(ssns?|social security numbers?|passwords?|credentials|all (patient )?records)\b",
}
REASONS = {
    "ignore_previous": "asks the reader to ignore or override earlier instructions",
    "fake_role_tag": "imitates a system/assistant role marker",
    "addressed_to_ai": "addresses AI assistants directly",
    "persona_switch": "tries to switch the assistant's persona or mode",
    "forced_output": "dictates the exact output",
    "prompt_extraction": "asks for the system prompt or hidden configuration",
    "markdown_image": "embeds a remote markdown image (zero-click exfiltration)",
    "credential_request": "asks for passwords or credentials",
    "hidden_comment": "contains a hidden HTML comment",
    "permission_change": "tries to change permissions or roles",
    "data_exfiltration": "asks to output identifiers, credentials or bulk records",
}
COMPILED = {k: re.compile(v, re.IGNORECASE | re.DOTALL | re.MULTILINE) for k, v in RULES.items()}


def normalise(text: str) -> str:
    return unicodedata.normalize("NFKC", text).translate(ZERO_WIDTH)


def scan(text: str) -> list[str]:
    """Names of the rules that fire on this text (empty list = looks clean)."""
    t = normalise(text)
    return [name for name, rx in COMPILED.items() if rx.search(t)]


def screen(chunks: list[Chunk]) -> tuple[list[Chunk], list[dict]]:
    """Split chunks into (clean, flagged). Flagged entries carry the chunk ID and
    human-readable reasons, never the chunk text."""
    clean, flagged = [], []
    for c in chunks:
        hits = scan(c.text)
        if hits:
            flagged.append({"chunk_id": c.chunk_id, "rules": hits, "reasons": [REASONS[h] for h in hits]})
        else:
            clean.append(c)
    return clean, flagged
