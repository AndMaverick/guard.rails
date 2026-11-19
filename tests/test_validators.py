import unittest

from guard_rails import validators as v


class ChecksumTests(unittest.TestCase):
    def test_luhn_published_test_cards(self):
        for number in ("4111111111111111", "5500 0000 0000 0004", "3782 822463 10005", "6011111111111117"):
            self.assertTrue(v.luhn_valid(number), number)

    def test_luhn_rejects_off_by_one_and_bad_length(self):
        self.assertFalse(v.luhn_valid("4111111111111112"))
        self.assertFalse(v.luhn_valid("411111111111"))  # 12 digits
        self.assertFalse(v.luhn_valid("41111111111111111111"))  # 20 digits

    def test_iban_published_examples(self):
        for iban in ("GB82 WEST 1234 5698 7654 32", "DE89370400440532013000", "AE07 0331 2345 6789 0123 456", "SA0380000000608010167519"):
            self.assertTrue(v.iban_valid(iban), iban)

    def test_iban_rejects_changed_digit_and_junk(self):
        self.assertFalse(v.iban_valid("GB82 WEST 1234 5698 7654 33"))
        self.assertFalse(v.iban_valid("ABCD"))
        self.assertFalse(v.iban_valid("1234567890123456"))

    def test_emirates_id(self):
        self.assertTrue(v.emirates_id_valid("784-1985-1234567-3"))
        self.assertTrue(v.emirates_id_valid("784198512345673"))
        self.assertFalse(v.emirates_id_valid("784-1985-1234567-4"))
        self.assertFalse(v.emirates_id_valid("123-1985-1234567-3"))

    def test_saudi_id(self):
        self.assertTrue(v.saudi_id_valid("1234567897"))
        self.assertTrue(v.saudi_id_valid("2000000006"))
        self.assertFalse(v.saudi_id_valid("1234567890"))
        self.assertFalse(v.saudi_id_valid("3000000008"))  # must start 1 or 2

    def test_nik(self):
        self.assertTrue(v.nik_valid("3171011504900001"))  # Jakarta, born 15 April 1990
        self.assertTrue(v.nik_valid("3171015504900001"))  # a woman: day plus 40
        self.assertFalse(v.nik_valid("0071011504900001"))  # no such province
        self.assertFalse(v.nik_valid("3171013113900001"))  # month 13
        self.assertFalse(v.nik_valid("3171013002900001"))  # 30 February

    def test_ssn(self):
        self.assertTrue(v.ssn_valid("123-45-6789"))
        for bad in ("000-12-3456", "666-12-3456", "900-12-3456", "123-00-6789", "123-45-0000"):
            self.assertFalse(v.ssn_valid(bad), bad)

    def test_nino(self):
        self.assertTrue(v.nino_valid("AB 12 34 56 C"))
        self.assertFalse(v.nino_valid("QQ 12 34 56 C"))
        self.assertFalse(v.nino_valid("BG 12 34 56 C"))
        self.assertFalse(v.nino_valid("AB 12 34 56 E"))

    def test_entropy(self):
        self.assertEqual(v.entropy(""), 0.0)
        self.assertAlmostEqual(v.entropy("aabb"), 1.0)
        self.assertFalse(v.high_entropy("aaaaaaaaaaaaaaaaaaaaaaaaaaaa"))
        self.assertTrue(v.high_entropy("Zq8Lm2Xp9Rt4Vb7Nc3Kd6Hs1Wf5Jg0Yy"))


if __name__ == "__main__":
    unittest.main()
