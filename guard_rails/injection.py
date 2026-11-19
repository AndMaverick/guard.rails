"""Prompt-injection scoring: weighted patterns over text that has been normalised the way attackers try to evade.

This is a heuristic. It catches the common, copied and careless attacks in many languages and the cheapest
evasions (invisible characters, compatibility forms, Latin look-alike letters). A determined attacker rephrases,
so a score of zero means "nothing obvious", never "safe".
"""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from re import Pattern

_INVISIBLE = dict.fromkeys(map(ord, "​‌‍⁠﻿­‪‫‬‭‮⁦⁧⁨⁩"), None)
# Cyrillic and Greek letters that read as Latin. Used to unmask "ignоre" written with a Cyrillic o.
_HOMOGLYPHS = {ord(k): v for k, v in {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ј": "j",
    "ѕ": "s", "һ": "h", "Α": "A", "Β": "B", "Ε": "E", "Η": "H", "Ι": "I", "Κ": "K", "Μ": "M",
    "Ν": "N", "Ο": "O", "Ρ": "P", "Τ": "T", "Χ": "X", "ο": "o", "ι": "i",
}.items()}


def _p(text: str, flags: int = re.I) -> Pattern[str]:
    return re.compile(text, flags)


@dataclass(frozen=True)
class Rule:
    label: str
    pattern: Pattern[str]
    weight: int
    latin_view: bool = True  # also try the homoglyph-folded text


# Weight 3 alone reaches the default threshold of 3.
RULES: list[Rule] = [
    Rule("override.en", _p(r"ignore (?:all |any |every )?(?:of )?(?:the )?(?:previous|prior|above|earlier|preceding) (?:instructions|prompts?|directions|rules|messages)"), 3),
    Rule("disregard.en", _p(r"disregard (?:the |your |all )?(?:system|previous|above|prior|earlier)"), 3),
    Rule("forget.en", _p(r"forget (?:everything|all) (?:you|that you) (?:were|have been) (?:told|instructed)|forget your (?:instructions|rules|guidelines)"), 3),
    Rule("reveal.en", _p(r"(?:reveal|show|print|repeat|output|display|leak) (?:me )?(?:your |the )?(?:system|hidden|initial|original) (?:prompt|instructions?|message)"), 3),
    Rule("verbatim.en", _p(r"(?:repeat|print|output) (?:everything|all|the text) (?:above|before)(?: this)?(?: verbatim| word for word)?"), 2),
    Rule("persona.en", _p(r"you are now (?:in )?(?:developer|dan|jailbreak|an? unrestricted|an? unfiltered)"), 2),
    Rule("dan.en", _p(r"\bdo anything now\b|\bdeveloper mode (?:enabled|activated|on)\b"), 2),
    Rule("norules.en", _p(r"pretend (?:you have|there are|that you have) no (?:rules|restrictions|limits|guidelines)|without (?:any )?(?:restrictions|filters|safety)"), 2),
    Rule("newinstr.en", _p(r"(?:^|\n)\s*(?:new|updated|override) (?:system )?instructions?\s*:"), 2),
    Rule("fromnow.en", _p(r"from now on,? (?:you|ignore|disregard|act|respond|only)"), 1),
    Rule("roletag", _p(r"</?(?:system|assistant|developer)>|\[/?(?:system|inst)\]|<\|(?:im_start|im_end|system)\|>"), 2),
    Rule("delimiter", _p(r"(?:^|\n)\s*#{2,}\s*(?:system|instruction)s?\b|(?:^|\n)\s*system\s*:\s*you\b"), 2),
    Rule("exfil.markdown", _p(r"!\[[^\]]*\]\(https?://[^)\s]*[?&][^)\s]*=(?:\{|\[|%7B)?[^)\s]*\)"), 2),
    Rule("override.es", _p(r"ignora (?:todas )?las instrucciones anteriores|olvida (?:todas )?tus instrucciones"), 3, False),
    Rule("override.fr", _p(r"ignore[zr]? (?:toutes )?les instructions pr[ée]c[ée]dentes|oublie[zr]? (?:toutes )?tes instructions"), 3, False),
    Rule("override.de", _p(r"ignorier(?:e|en)? (?:alle |die )?(?:vorherigen|bisherigen|obigen) (?:anweisungen|instruktionen)"), 3, False),
    Rule("override.pt", _p(r"ignor[ae] (?:todas as )?instru[çc][õo]es anteriores"), 3, False),
    Rule("override.it", _p(r"ignora (?:tutte le )?istruzioni precedenti"), 3, False),
    Rule("override.id", _p(r"abaikan (?:semua )?instruksi (?:sebelumnya|di atas)|lupakan (?:semua )?instruksi"), 3, False),
    Rule("override.tr", _p(r"[öo]nceki (?:t[úu]m )?(?:talimatlar[ıi]|y[öo]nergeleri) (?:yoksay|g[öo]rmezden gel)"), 3, False),
    Rule("override.ru", _p(r"(?:игнорируй|забудь)(?: все)? (?:предыдущие|прошлые|твои) инструкции"), 3, False),
    Rule("override.ar", _p("تجاهل (?:جميع |كل )?التعليمات السابقة|انس (?:جميع |كل )?التعليمات"), 3, False),
    Rule("override.fa", _p("دستورات قبلی را نادیده بگیر"), 3, False),
    Rule("override.hi", _p("पिछले निर्देशों को अनदेखा कर"), 3, False),
    Rule("override.zh", _p("忽略(?:之前|以上|先前|上面)的(?:所有)?(?:指令|指示|提示)"), 3, False),
    Rule("override.ja", _p("(?:以前|前)の(?:指示|命令)(?:を|は)?(?:すべて)?(?:無視|忘れ)"), 3, False),
    Rule("override.ko", _p("(?:이전|위)의? ?(?:모든 )?(?:지침|지시|명령)(?:을|를)? ?무시"), 3, False),
]


def normalise(text: str) -> str:
    """Fold compatibility forms and drop invisible and bidirectional control characters."""
    return unicodedata.normalize("NFKC", text).translate(_INVISIBLE)


def explain(text: str) -> list[tuple[str, int]]:
    """The rules that matched, as (label, weight). Each rule counts once."""
    folded = normalise(text)
    latin = folded.translate(_HOMOGLYPHS)
    hits = []
    for rule in RULES:
        if rule.pattern.search(folded) or (rule.latin_view and rule.pattern.search(latin)):
            hits.append((rule.label, rule.weight))
    return hits


def injection_score(text: str) -> int:
    return sum(weight for _label, weight in explain(text))
