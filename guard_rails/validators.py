"""Checksums and structural rules that separate a real identifier from a digit string that merely looks like one.

Every validator takes the matched text, ignores separators, and returns a bool. None of them proves that an
identifier is issued to a person, only that it is well formed, which is what keeps a redactor from eating order
numbers, timestamps and phone-like noise.
"""
from __future__ import annotations

import math
import re
from collections import Counter
from datetime import date


def _digits(text: str) -> str:
    return "".join(c for c in text if c.isdigit())


def luhn(digits: str) -> bool:
    """The Luhn mod-10 checksum over any number of digits."""
    nums = [int(c) for c in digits if c.isdigit()]
    if len(nums) < 2:
        return False
    total = 0
    for index, value in enumerate(reversed(nums)):
        if index % 2 == 1:
            value *= 2
            if value > 9:
                value -= 9
        total += value
    return total % 10 == 0


def luhn_valid(text: str) -> bool:
    """A payment card number: 13 to 19 digits passing Luhn."""
    return 13 <= len(_digits(text)) <= 19 and luhn(text)


def iban_valid(text: str) -> bool:
    """ISO 13616: 15 to 34 characters, and the rearranged number is congruent to 1 modulo 97."""
    iban = text.replace(" ", "").upper()
    if not 15 <= len(iban) <= 34 or not iban.isalnum() or not iban[:2].isalpha() or not iban[2:4].isdigit():
        return False
    rearranged = iban[4:] + iban[:4]
    return int("".join(str(int(ch, 36)) for ch in rearranged)) % 97 == 1


def emirates_id_valid(text: str) -> bool:
    """UAE Emirates ID: 15 digits, the country code 784 first, and a Luhn check digit."""
    d = _digits(text)
    return len(d) == 15 and d.startswith("784") and luhn(d)


def saudi_id_valid(text: str) -> bool:
    """Saudi national or iqama number: 10 digits, starting 1 (citizen) or 2 (resident), with a Luhn check digit."""
    d = _digits(text)
    return len(d) == 10 and d[0] in "12" and luhn(d)


_NIK_PROVINCES = {*range(11, 22), *range(31, 37), 51, 52, 53, *range(61, 66), *range(71, 77), 81, 82, *range(91, 97)}


def nik_valid(text: str) -> bool:
    """Indonesian NIK: 16 digits, a real province code, and a birth date (the day is plus 40 for women)."""
    d = _digits(text)
    if len(d) != 16 or int(d[:2]) not in _NIK_PROVINCES or d[2:6] == "0000":
        return False
    day, month, year = int(d[6:8]), int(d[8:10]), int(d[10:12])
    day = day - 40 if day > 40 else day
    for century in (2000, 1900):
        try:
            if date(century + year, month, day) <= date.today():
                return True
        except ValueError:
            continue
    return False


def ssn_valid(text: str) -> bool:
    """US Social Security number format: no zero group, area not 000, 666 or 900 to 999, serial not 0000."""
    d = _digits(text)
    if len(d) != 9:
        return False
    area, group, serial = int(d[:3]), int(d[3:5]), int(d[5:])
    return area not in (0, 666) and area < 900 and group != 0 and serial != 0


_NINO_BAD_PREFIX = {"BG", "GB", "KN", "NK", "NT", "TN", "ZZ"}


def nino_valid(text: str) -> bool:
    """UK National Insurance number structure: allowed prefix letters, six digits, a suffix A to D."""
    t = text.replace(" ", "").upper()
    if not re.fullmatch(r"[A-Z]{2}\d{6}[A-D]", t):
        return False
    return not (t[0] in "DFIQUV" or t[1] in "DFIQUVO" or t[:2] in _NINO_BAD_PREFIX)


def entropy(text: str) -> float:
    """Shannon entropy in bits per character."""
    if not text:
        return 0.0
    counts = Counter(text)
    return -sum(n / len(text) * math.log2(n / len(text)) for n in counts.values())


def high_entropy(text: str, minimum_length: int = 24, threshold: float = 4.0) -> bool:
    """A long token with the character spread of a random secret, not of a word or a path."""
    return len(text) >= minimum_length and entropy(text) >= threshold
