import random
import unittest

from guard_rails import Pseudonymizer, StreamRedactor, redact


def _key():
    return "".join(("sk-", "ant-api03-", "A1b2C3d4E5f6G7h8I9j0"))


class PseudonymTests(unittest.TestCase):
    def test_round_trip(self):
        p = Pseudonymizer()
        safe = p.pseudonymize("Refund ana@example.com and bob@example.com, then email ana@example.com again.")
        self.assertEqual(safe, "Refund [EMAIL_1] and [EMAIL_2], then email [EMAIL_1] again.")
        reply = "Done. I wrote to [EMAIL_1] and [EMAIL_2]."
        self.assertEqual(p.restore(reply), "Done. I wrote to ana@example.com and bob@example.com.")

    def test_kinds_are_numbered_separately(self):
        p = Pseudonymizer()
        self.assertEqual(p.pseudonymize("ana@example.com 10.0.0.1"), "[EMAIL_1] [IP_1]")

    def test_unknown_tokens_are_left_alone(self):
        self.assertEqual(Pseudonymizer().restore("see [EMAIL_9]"), "see [EMAIL_9]")

    def test_repr_hides_values(self):
        p = Pseudonymizer()
        p.pseudonymize("ana@example.com")
        self.assertNotIn("ana", repr(p))
        self.assertEqual(len(p), 1)

    def test_only_limits_what_is_swapped(self):
        self.assertEqual(Pseudonymizer(only=["IP"]).pseudonymize("ana@example.com 10.0.0.1"), "ana@example.com [IP_1]")


class StreamTests(unittest.TestCase):
    TEXT = ("Hello. Card 4111 1111 1111 1111 and mail ana@example.com, host 10.0.0.12, key " + "KEY" +
            " done. Another card 5500 0000 0000 0004 end.").replace("KEY", _key())

    def run_chunks(self, chunks, hold=128):
        s = StreamRedactor(hold=hold)
        return "".join(s.feed(c) for c in chunks) + s.flush()

    def test_matches_whole_text_redaction_for_any_chunking(self):
        expected = redact(self.TEXT)[0]
        rng = random.Random(7)
        for _ in range(300):
            cuts = sorted(rng.sample(range(1, len(self.TEXT)), rng.randint(1, 25)))
            chunks = [self.TEXT[a:b] for a, b in zip([0, *cuts], [*cuts, len(self.TEXT)], strict=True)]
            self.assertEqual(self.run_chunks(chunks), expected)

    def test_character_by_character(self):
        self.assertEqual(self.run_chunks(list(self.TEXT)), redact(self.TEXT)[0])

    def test_nothing_sensitive_is_released_early(self):
        s = StreamRedactor(hold=32)
        released = ""
        for ch in self.TEXT:
            released += s.feed(ch)
            self.assertNotIn("4111", released)
            self.assertNotIn("ana@example", released)
            self.assertNotIn(_key(), released)

    def test_unterminated_private_key_is_never_released(self):
        head = "".join(("-----BEGIN ", "RSA PRIVATE KEY-----\n"))
        s = StreamRedactor(hold=16)
        out = s.feed("intro " + head) + s.feed("MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu" * 3)
        self.assertNotIn("MIIB", out)
        out += s.feed("\n-----END RSA PRIVATE KEY-----\ndone") + s.flush()
        self.assertEqual(out, "intro [PRIVATE_KEY]\ndone")

    def test_empty_and_flush_twice(self):
        s = StreamRedactor()
        self.assertEqual(s.feed(""), "")
        self.assertEqual(s.flush(), "")
        self.assertEqual(s.flush(), "")

    def test_bad_hold(self):
        with self.assertRaises(ValueError):
            StreamRedactor(hold=0)


if __name__ == "__main__":
    unittest.main()
