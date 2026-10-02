import struct
import unittest
from recyclerecordreview import inspect


def sample(v=2, path="C:\\Users\\Synthetic\\item.txt"):
    raw = (path + "\0").encode("utf-16-le")
    prefix = struct.pack("<QQQ", v, 123, 133000000000000000)
    return prefix + (
        raw.ljust(520, b"\0") if v == 1 else struct.pack("<I", len(raw) // 2) + raw
    )


class Tests(unittest.TestCase):
    def test_versions(self):
        for v in (1, 2):
            r = inspect(sample(v))
            self.assertEqual(r["status"], "PASS")
            self.assertEqual(r["records"][0]["declared_size"], 123)

    def test_private(self):
        self.assertNotIn("Synthetic", str(inspect(sample())))

    def test_unknown(self):
        self.assertEqual(inspect(sample(3))["status"], "OPEN")

    def test_truncated_every_prefix(self):
        d = sample()
        for i in range(len(d)):
            self.assertNotEqual(inspect(d[:i])["status"], "PASS")

    def test_extra(self):
        self.assertEqual(inspect(sample() + b"x")["status"], "FAIL")

    def test_surrogate(self):
        self.assertEqual(
            inspect(sample(path="x")[:-4] + b"\x00\xd8\x00\x00")["status"], "FAIL"
        )

    def test_missing_null(self):
        self.assertEqual(inspect(sample(path="x")[:-2] + b"xx")["status"], "FAIL")

    def test_limit(self):
        self.assertEqual(inspect(b"x" * (16 * 1024 * 1024 + 1))["status"], "FAIL")
