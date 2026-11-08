# guard.rails

Defensive checks to run on text before it reaches a model and after it comes back: PII redaction, prompt-injection scoring, and a policy object that returns a clear verdict with reasons. Standard library only.

## Use

```python
from guard_rails import Policy

policy = Policy(max_chars=8000, blocked_terms=("internal only",))
verdict = policy.check("Email me at lee@corp.io")

verdict.allowed      # True
verdict.clean_text   # 'Email me at [EMAIL]'
verdict.reasons      # [] when allowed, otherwise every reason it was blocked
```

## What it does

- **Redaction.** Emails, IPv4 addresses, phone numbers, and payment cards become typed placeholders. Card candidates are only redacted when they pass the Luhn check, so order numbers and ids are left alone.
- **Injection scoring.** Weighted patterns for instruction override, system prompt extraction, jailbreak personas, and role tag spoofing. The policy blocks at a threshold you set.
- **Verdicts, not exceptions.** Length, injection, and blocked terms are all evaluated, and every failing reason is returned together so the caller can log or explain it.

## Honest limits

These are heuristics. They catch the common and the lazy, and they make a useful first layer, but they do not replace least-privilege tool access, output validation, and human approval for risky actions. See the Action layer in [mao-framework](https://github.com/AndMaverick/mao-framework).

## Tests

```
python -m unittest discover -s tests -t . -v
```

MIT licensed. Built by [AndMaverick LLC](https://www.andmaverick.com).

---

**Related reading:** [Nobody Signs for the Agent](https://blog.andmaverick.com/nobody-signs-for-the-agent?utm_source=github&utm_medium=repo&utm_campaign=guard.rails)

**If this is your problem.** If a system you run can fail in ways that matter, the controls belong in the architecture, not in the postmortem. I am happy to talk through yours. [Begin a conversation](https://calendly.com/andmaverick?utm_source=github&utm_medium=repo&utm_campaign=guard.rails).
