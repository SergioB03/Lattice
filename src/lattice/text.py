"""Text hygiene: normalisation, slugs, similarity and injection heuristics."""

from __future__ import annotations

import difflib
import re
import unicodedata

# Control characters, zero-width characters and bidi overrides that can hide text from humans.
_INVISIBLE = re.compile(
    "[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff]"
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
    # Directives addressed to whoever reads this later: the stored-injection shape.
    r"\b(agents?|assistants?|ais?|llms?|models?|bots?)\b[^.\n]{0,30}\b(reading|that reads?|should|must|always|never)\b",
    r"\b(note|message|reminder) (to|for) (all )?(agents?|assistants?|ais?|llms?|models?)\b",
    r"\b(pre-?approved|delegated|granted)\b[^.\n]{0,40}\b(rights?|access|permissions?|approval|owner)\b",
    r"\bwithout (asking|review|approval|confirmation)\b",
    r"\bneeds? no (review|approval)\b",
    r"\bwhen (summari[sz]ing|answering|asked)\b[^.\n]{0,60}\b(always|never|say|describe|claim)\b",
]
_INSTRUCTION_RE = re.compile("|".join(_INSTRUCTION_PATTERNS), re.IGNORECASE)


# Latin look-alikes from Cyrillic and Greek (subset of Unicode TR39 confusables). Used only for
# comparison keys, so "Skуlr" (Cyrillic у) collides with "Skylr" instead of slipping past dedup.
_CONFUSABLES = str.maketrans({
    "а": "a", "в": "b", "е": "e", "ё": "e", "к": "k", "м": "m", "н": "h", "о": "o", "р": "p", "с": "c", "т": "t",
    "у": "y", "х": "x", "ѕ": "s", "і": "i", "ј": "j", "ԁ": "d", "ɡ": "g", "ӏ": "l", "ο": "o", "α": "a", "ε": "e",
    "ι": "i", "κ": "k", "ν": "v", "ρ": "p", "τ": "t", "υ": "u", "χ": "x", "ω": "w", "ℓ": "l", "ı": "i",
})


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
    text = text.casefold().translate(_CONFUSABLES)
    text = re.sub(r"[^\w]+", " ", text)
    return text.strip()


def slugify(text: str) -> str:
    s = norm_key(text).replace("_", " ")
    s = re.sub(r"\s+", "-", s).strip("-")
    return (s or "x")[:48].strip("-")


_SKELETON = [("rn", "m"), ("vv", "w"), ("1", "l"), ("i", "l"), ("|", "l"), ("0", "o")]


def skeleton(text: str) -> str:
    """Visual skeleton for look-alike comparison: SkyIr, Sky1r and Skylr share one."""
    s = norm_key(text)
    for a, b in _SKELETON:
        s = s.replace(a, b)
    return s


def similarity_bp(a: str, b: str) -> int:
    """Name similarity in basis points (0..10000). Deterministic and dependency-free."""
    ka, kb = norm_key(a), norm_key(b)
    if not ka or not kb:
        return 0
    if ka == kb:
        return 10000
    if skeleton(a) == skeleton(b):
        return 9900  # look-alike spelling: duplicate band, but distinguishable from an exact match
    if re.findall(r"\d+", ka) != re.findall(r"\d+", kb):
        # "Sprint 12" vs "Sprint 13", "Room 101" vs "Room 102": different numbers mean different things.
        ka_, kb_ = re.sub(r"\d+", "#", ka), re.sub(r"\d+", "#", kb)
        return min(8000, round(difflib.SequenceMatcher(None, ka_, kb_, autojunk=False).ratio() * 10000))  # look-alike spelling: duplicate band, but distinguishable from an exact match
    ratio = difflib.SequenceMatcher(None, ka, kb, autojunk=False).ratio()
    # Token-set view catches reordered names ("Banuelos Sergio").
    ta, tb = set(ka.split()), set(kb.split())
    token = len(ta & tb) / max(len(ta | tb), 1)
    # Containment: "Lattice KG" vs "Lattice" is a likely variant of the same thing.
    small, big = sorted((ta, tb), key=len)
    contained = 0.88 if small < big and len(small) * 2 >= len(big) else 0.0
    return round(max(ratio, token, contained) * 10000)


def looks_like_instruction(text: str) -> bool:
    return bool(_INSTRUCTION_RE.search(text or ""))


def estimate_tokens(text: str) -> int:
    """Declared token counter: ceil(chars / 4). Deterministic so evals reproduce."""
    return (len(text) + 3) // 4


def quote(text: str) -> str:
    """Fence stored text so a reading agent treats it as data, not instructions."""
    return "«" + text.replace("«", "‹").replace("»", "›").replace("\n", " ⏎ ") + "»"
