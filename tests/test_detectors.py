import unittest

from guard_rails import DETECTORS, find, kinds, redact


def _secret(*parts):
    """Built at run time so the repository never contains a string that looks like a live credential."""
    return "".join(parts)


class DetectorTests(unittest.TestCase):
    def kinds_in(self, text):
        return [f.kind for f in find(text)]

    def test_kinds_listed(self):
        for k in ("EMAIL", "CARD", "IBAN", "EMIRATES_ID", "NIK", "SSN", "SAUDI_ID", "NINO", "IP", "PHONE", "PRIVATE_KEY", "ANTHROPIC_KEY"):
            self.assertIn(k, kinds())
        self.assertEqual(len({d.kind for d in DETECTORS}), len(DETECTORS))

    def test_positions_refer_to_original_text(self):
        text = "mail ana@example.com now"
        (f,) = find(text)
        self.assertEqual((f.kind, text[f.start:f.end]), ("EMAIL", "ana@example.com"))

    def test_identifiers_across_countries(self):
        self.assertEqual(self.kinds_in("Emirates ID 784-1985-1234567-3"), ["EMIRATES_ID"])
        self.assertEqual(self.kinds_in("NIK 3171011504900001"), ["NIK"])
        self.assertEqual(self.kinds_in("iqama 2000000006"), ["SAUDI_ID"])
        self.assertEqual(self.kinds_in("ssn 123-45-6789"), ["SSN"])
        self.assertEqual(self.kinds_in("NI AB 12 34 56 C"), ["NINO"])
        self.assertEqual(self.kinds_in("pay GB82 WEST 1234 5698 7654 32"), ["IBAN"])
        self.assertEqual(self.kinds_in("pay AE07 0331 2345 6789 0123 456"), ["IBAN"])

    def test_lookalikes_are_left_alone(self):
        for text in ("order 1234 5678 9012 3456", "invoice 20240131123456", "ref GB82 WEST 1234 5698 7654 33", "version 1.2.3.4.5", "number 1234567890"):
            self.assertEqual([k for k in self.kinds_in(text) if k in ("CARD", "IBAN", "NIK", "SAUDI_ID", "IP")], [], text)

    def test_arabic_and_persian_digits(self):
        arabic = "٤١١١ ١١١١ ١١١١ ١١١١"
        clean, findings = redact(f"بطاقتي {arabic} شكرا")
        self.assertEqual(clean, "بطاقتي [CARD] شكرا")
        self.assertEqual(findings[0].kind, "CARD")
        persian = "۴۱۱۱۱۱۱۱۱۱۱۱۱۱۱۱"
        self.assertEqual(self.kinds_in(persian), ["CARD"])

    def test_secrets(self):
        cases = {
            "ANTHROPIC_KEY": _secret("sk-", "ant-api03-", "A1b2C3d4E5f6G7h8I9j0"),
            "AWS_KEY": _secret("AKIA", "ABCDEFGHIJKLMNOP"),
            "GITHUB_TOKEN": _secret("gh", "p_", "a" * 36),
            "SLACK_TOKEN": _secret("xo", "xb-", "1234567890-abcdefghij"),
            "STRIPE_KEY": _secret("sk", "_live_", "a1B2c3D4e5F6g7H8"),
            "GOOGLE_KEY": _secret("AI", "za", "A" * 35),
            "JWT": _secret("ey", "JhbGciOiJIUzI1NiJ9.", "ey", "JzdWIiOiIxMjM0NTY3ODkwIn0.", "dBjftJeZ4CVPmB92K27uhbUJU1p1r"),
            "API_KEY": _secret("sk-", "proj-", "A" * 40),
        }
        for kind, value in cases.items():
            found = find(f"token: {value} end")
            self.assertEqual([f.kind for f in found], [kind], kind)
            self.assertEqual(found[0].category, "secret")
            self.assertNotIn(value, redact(f"token: {value} end")[0])

    def test_private_key_block_redacted_whole(self):
        block = _secret("-----BEGIN ", "RSA PRIVATE KEY-----\nMIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu\n-----END ", "RSA PRIVATE KEY-----")
        clean, findings = redact(f"before\n{block}\nafter")
        self.assertEqual(clean, "before\n[PRIVATE_KEY]\nafter")
        self.assertEqual(findings[0].category, "secret")

    def test_overlap_prefers_the_more_specific_detector(self):
        # an Emirates ID is also a 15 digit run that could pass as a card or phone: it must be reported once, as the ID
        found = find("784-1985-1234567-3")
        self.assertEqual([f.kind for f in found], ["EMIRATES_ID"])

    def test_only_filters_kinds(self):
        text = "ana@example.com 10.0.0.1"
        self.assertEqual([f.kind for f in find(text, only=["IP"])], ["IP"])

    def test_custom_placeholder(self):
        clean, _ = redact("ana@example.com", placeholder=lambda f: "#" * (f.end - f.start))
        self.assertEqual(clean, "#" * 15)

    def test_untouched_text_is_identical(self):
        text = "Quarterly revenue grew 12 percent in 2024 across 3 regions."
        self.assertEqual(redact(text), (text, []))

    def test_unicode_text_around_findings_is_preserved(self):
        text = "你好 ana@example.com 谢谢 \U0001f600"
        self.assertEqual(redact(text)[0], "你好 [EMAIL] 谢谢 \U0001f600")


if __name__ == "__main__":
    unittest.main()
