# guard.rails

[![CI](https://github.com/AndMaverick/guard.rails/actions/workflows/ci.yml/badge.svg)](https://github.com/AndMaverick/guard.rails/actions/workflows/ci.yml)

Defensive checks for text going into and coming out of a language model. Personal data and secrets are found with the checksum or structure that real identifiers have, so order numbers and timestamps are left alone. Prompt injection is scored in fifteen languages. Standard library only, typed, Python 3.10 and up.

```
pip install git+https://github.com/AndMaverick/guard.rails
```

## Use

```python
from guard_rails import Policy

policy = Policy(max_chars=8000, blocked_terms=("internal only",))
verdict = policy.check("Email me at lee@corp.io")

verdict.allowed      # True
verdict.clean_text   # 'Email me at [EMAIL]'
verdict.reasons      # [] when allowed, otherwise every reason it was blocked
verdict.matched      # the injection rules that fired, for logs and tuning
verdict.to_dict()    # a log-safe record: kinds and positions, never the values
```

### Send a model safe text, then restore the answer

```python
from guard_rails import Pseudonymizer

p = Pseudonymizer()
safe = p.pseudonymize("Refund ana@example.com, copy bob@example.com")
# 'Refund [EMAIL_1], copy [EMAIL_2]'   <- this is what the model sees
answer = model(safe)
p.restore(answer)                        # real addresses back in, for tokens this object issued
```

The same value always gets the same token inside one object. Keep the object in memory and scope it to one request. Its mapping is exactly the data you removed.

### Redact a stream without a card number slipping through a chunk boundary

```python
from guard_rails import StreamRedactor

s = StreamRedactor(hold=128)
for chunk in model_stream:
    emit(s.feed(chunk))
emit(s.flush())
```

Releases only text that cannot belong to a later match, and holds an unterminated private key block until it closes. Tests check that every chunking of a text, down to one character at a time, gives the same result as redacting the whole text.

### Command line

```
echo "mail ana@example.com" | python -m guard_rails redact
python -m guard_rails scan notes.txt        # findings as JSON, no values
python -m guard_rails check --block-pii out.txt && echo ok
```

## What it detects

| Kind | Rule |
|---|---|
| CARD | 13 to 19 digits, Luhn |
| IBAN | ISO 13616 mod-97 (UAE, Saudi, UK, EU and the rest) |
| EMIRATES_ID | 15 digits, starts 784, Luhn |
| SAUDI_ID | 10 digits, starts 1 or 2, Luhn (citizen and iqama) |
| NIK | Indonesian ID: 16 digits, real province, valid birth date (day plus 40 for women) |
| SSN, NINO | US and UK structure rules |
| EMAIL, IP, PHONE | pattern, with length and neighbour-digit checks |
| Secrets | private key blocks, JWT, AWS, GitHub, Slack, Stripe, Google, Anthropic and OpenAI-style keys |

Arabic-Indic and Persian digits are folded before matching, and positions refer to the original text, so a message in any script keeps its own words. Where two detectors claim the same span, the more specific one wins, so an Emirates ID is reported once as an Emirates ID.

Injection scoring covers English, Spanish, French, German, Portuguese, Italian, Indonesian, Turkish, Russian, Arabic, Persian, Hindi, Chinese, Japanese and Korean, plus role-tag spoofing, template markers and markdown-image exfiltration. Zero-width characters, bidirectional controls, compatibility forms and Cyrillic or Greek look-alike letters are normalised first.

## Honest limits

These are heuristics, and this is not a security boundary.

- An identifier that passes its checksum is well formed. It is not proven to belong to a person, and a person's name or address has no checksum, so names and street addresses are not detected.
- A clean injection score means nothing obvious was found. An attacker who rephrases gets past phrase rules. Keep the real controls (scope, risk tier, human approval) in the layer that acts, for example the Action layer in [mao-framework](https://github.com/AndMaverick/mao-framework), and use `guard_verifier` there to fail a step whose output breaks policy.
- Credential detection covers common formats. A key in a custom format is not found unless you add a `Detector`.

## Tests

```
python -m unittest discover -s tests -t . -v
```

Test credentials are assembled at run time so the repository never contains a string that looks like a live key.

MIT licensed. Built by [AndMaverick LLC](https://www.andmaverick.com).

---

**Related reading:** [Nobody Signs for the Agent](https://blog.andmaverick.com/nobody-signs-for-the-agent?utm_source=github&utm_medium=repo&utm_campaign=guard.rails)

**If this is your problem.** If a system you run can fail in ways that matter, the controls belong in the architecture, not in the postmortem. I am happy to talk through yours. [Begin a conversation](https://calendly.com/andmaverick?utm_source=github&utm_medium=repo&utm_campaign=guard.rails).
