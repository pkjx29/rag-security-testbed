"""Defences against indirect prompt injection in retrieved text.

D4 "spotlighting" (Hines et al., 2024): each retrieved chunk is wrapped in
   <document> tags and the system prompt says that text inside them is data, not
   instructions. This is a prompt-only change, so it costs nothing at runtime.

D5 rule-based chunk filter: a regex scanner flags retrieved chunks that look
   like instructions aimed at an AI system; flagged chunks are dropped before
   the prompt is built.

Caveat, stated in the README: the same person wrote these rules and the attack
suite. The rules target phrasings common in publicly documented prompt-
injection examples and were not tuned per test case, but this is still the
most favourable setting a rule-based filter will get. The per-carrier breakdown in
results shows which phrasing styles get past it.
"""
import re
import unicodedata

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
}
COMPILED = {k: re.compile(v, re.IGNORECASE | re.DOTALL | re.MULTILINE) for k, v in RULES.items()}


def normalise(text: str) -> str:
    return unicodedata.normalize("NFKC", text).translate(ZERO_WIDTH)


def scan(text: str) -> list[str]:
    """Names of the rules that fire on this text (empty list = looks clean)."""
    t = normalise(text)
    return [name for name, rx in COMPILED.items() if rx.search(t)]


def filter_chunks(chunks: list[dict]) -> tuple[list[dict], list[dict]]:
    kept, dropped = [], []
    for c in chunks:
        (dropped if scan(c["text"]) else kept).append(c)
    return kept, dropped
