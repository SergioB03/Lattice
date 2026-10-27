"""Text hygiene: normalisation, slugs, similarity and injection heuristics."""

from __future__ import annotations

import difflib
import re
import unicodedata

# Control characters, zero-width characters and bidi overrides that can hide text from humans.
_INVISIBLE = re.compile(
    "[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f​-‏‪-‮⁠-⁤⁦-⁩﻿]"
)

# Phrases that read like instructions to a model rather than knowledge about the world.
# A match is not a verdict; it routes the proposal to human review.
_INSTRUCTION_PATTERNS = [
    r"\bignore (all|any|the|your|previous|prior|above)\b.{0,40}\b(instructions?|prompts?|rules?)\b",
    r"\bdisregard\b.{0,40}\b(instructions?|rules?|polic(y|ies))\b",
    r"\byou are now\b",
    r"\b(system|developer) (prompt|message)\b",
    r"\bnew instructions?\b",
    r"\bdo not (tell|inform|alert) (the )?(user|human|owner)\b",
    r"\b(run|execute) (this|the following) (command|code|script)\b",
    r"\bcurl\s+https?://",
    r"\b(approve|auto-?approve) (this|all) (proposals?|requests?)\b",
    r"<\s*/?\s*(system|assistant|tool|instructions?)\s*>",
]
_INSTRUCTION_RE = re.compile("|".join(_INSTRUCTION_PATTERNS), re.IGNORECASE)


def clean(text: str) -> str:
    """NFC-normalise, strip invisible/control characters, collapse whitespace runs."""
    text = unicodedata.normalize("NFC", text)
    text = _INVISIBLE.sub("", text)
    text = text.replace("\r\n", "\n").replace("\r", "\n").replace("\t", " ")
    text = re.sub(r"[ ]{2,}", " ", text)
    return text.strip()


def norm_key(text: str) -> str:
    """Comparison key for names and aliases: case-folded, accent-free, punctuation-light."""
    text = unicodedata.normalize("NFKD", clean(text))
    text = "".join(ch for ch in text if not unicodedata.combining(ch))
    text = text.casefold()
    text = re.sub(r"[^\w]+", " ", text)
    return text.strip()


def slugify(text: str) -> str:
    s = norm_key(text).replace("_", " ")
    s = re.sub(r"\s+", "-", s).strip("-")
    return (s or "x")[:48].strip("-")


def similarity_bp(a: str, b: str) -> int:
    """Name similarity in basis points (0..10000). Deterministic and dependency-free."""
    ka, kb = norm_key(a), norm_key(b)
    if not ka or not kb:
        return 0
    if ka == kb:
        return 10000
    ratio = difflib.SequenceMatcher(None, ka, kb, autojunk=False).ratio()
    # Token-set view catches reordered names ("Banuelos Sergio").
    ta, tb = set(ka.split()), set(kb.split())
    token = len(ta & tb) / max(len(ta | tb), 1)
    return int(round(max(ratio, token) * 10000))


def looks_like_instruction(text: str) -> bool:
    return bool(_INSTRUCTION_RE.search(text or ""))


def estimate_tokens(text: str) -> int:
    """Declared token counter: ceil(chars / 4). Deterministic so evals reproduce."""
    return (len(text) + 3) // 4


def quote(text: str) -> str:
    """Fence stored text so a reading agent treats it as data, not instructions."""
    return "«" + text.replace("«", "‹").replace("»", "›").replace("\n", " ⏎ ") + "»"
