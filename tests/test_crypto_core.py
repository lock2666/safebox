"""اختبارات محرك التشفير — شغّلها بـ: python -m unittest discover -s tests -v"""

from __future__ import annotations

import base64
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import crypto_core as cc
from passwords import estimate_strength


class RoundTripTests(unittest.TestCase):
    def setUp(self):
        self.data = os.urandom(5000) + "بيانات عربية للتشفير".encode("utf-8") * 20
        self.password = "كلمة-مرور-قوية-جدا-2026!"

    def test_password_roundtrip(self):
        blob = cc.encrypt_bytes(self.data, password=self.password, filename="ملفي.pdf")
        result = cc.decrypt_bytes(blob, password=self.password)
        self.assertEqual(result.data, self.data)
        self.assertEqual(result.name, "ملفي.pdf")

    def test_keyfile_roundtrip(self):
        key = cc.generate_key()
        blob = cc.encrypt_bytes(self.data, key=key, filename="photo.jpg")
        result = cc.decrypt_bytes(blob, key=key)
        self.assertEqual(result.data, self.data)
        self.assertEqual(result.name, "photo.jpg")

    def test_key_file_text_roundtrip(self):
        key = cc.generate_key()
        key_text = base64.urlsafe_b64encode(key).decode("ascii")
        blob = cc.encrypt_bytes(self.data, key=key, filename="a.bin")
        result = cc.decrypt_bytes(blob, key=key_text)
        self.assertEqual(result.data, self.data)

    def test_hex_key_roundtrip(self):
        key = cc.generate_key()
        blob = cc.encrypt_bytes(self.data, key=key)
        result = cc.decrypt_bytes(blob, key=key.hex())
        self.assertEqual(result.data, self.data)

    def test_raw_bytes_key_roundtrip(self):
        key = cc.generate_key()
        blob = cc.encrypt_bytes(self.data, key=key)
        result = cc.decrypt_bytes(blob, key=key)  # بايتات خام لا نص
        self.assertEqual(result.data, self.data)

    def test_key_file_with_comments(self):
        """ملفات المفتاح المُولَّدة من /api/keygen تحتوي تعليقات."""
        key = cc.generate_key()
        encoded = base64.urlsafe_b64encode(key).decode("ascii")
        key_file = f"# مفتاح «الخزنة» — لا تشاركه مع أحد.\n# سطر تعليق آخر\n{encoded}\n"
        blob = cc.encrypt_bytes(self.data, key=key_file, filename="a.pdf")
        result = cc.decrypt_bytes(blob, key=key_file)
        self.assertEqual(result.data, self.data)
        self.assertEqual(result.name, "a.pdf")

    def test_hide_name(self):
        blob = cc.encrypt_bytes(self.data, password=self.password,
                                filename="سر.txt", hide_name=True)
        result = cc.decrypt_bytes(blob, password=self.password)
        self.assertNotIn("سر", result.name)
        self.assertEqual(result.data, self.data)

    def test_text_roundtrip(self):
        text = "رسالة سرية: أنا أحب الأمن السيبراني 🔐"
        token = cc.encrypt_text(text, password=self.password)
        self.assertIsInstance(token, str)
        self.assertNotIn(text, token)
        self.assertEqual(cc.decrypt_text(token, password=self.password), text)

    def test_same_password_different_blobs(self):
        """نفس كلمة المرور ونفس البيانات لابد أن تنتج ملفات مختلفة (Salt/Nonce فريدان)."""
        first = cc.encrypt_bytes(self.data, password=self.password)
        second = cc.encrypt_bytes(self.data, password=self.password)
        self.assertNotEqual(first, second)

    def test_all_presets(self):
        for preset in cc.ITERATION_PRESETS:
            blob = cc.encrypt_bytes(self.data, password=self.password, preset=preset)
            self.assertEqual(cc.decrypt_bytes(blob, password=self.password).data, self.data)


class FailureTests(unittest.TestCase):
    def setUp(self):
        self.data = b"secret content"
        self.password = "Passw0rd-قوي-جدا-1234"

    def test_wrong_password(self):
        blob = cc.encrypt_bytes(self.data, password=self.password)
        with self.assertRaises(cc.WrongKeyError):
            cc.decrypt_bytes(blob, password="wrong-password")

    def test_wrong_key_file(self):
        blob = cc.encrypt_bytes(self.data, key=cc.generate_key())
        with self.assertRaises(cc.WrongKeyError):
            cc.decrypt_bytes(blob, key=cc.generate_key())

    def test_password_used_on_keyfile(self):
        blob = cc.encrypt_bytes(self.data, key=cc.generate_key())
        with self.assertRaises(cc.WrongKeyError):
            cc.decrypt_bytes(blob, password=self.password)

    def test_key_used_on_password_file(self):
        blob = cc.encrypt_bytes(self.data, password=self.password)
        with self.assertRaises(cc.WrongKeyError):
            cc.decrypt_bytes(blob, key=cc.generate_key())

    def test_missing_secret(self):
        blob = cc.encrypt_bytes(self.data, password=self.password)
        with self.assertRaises(cc.SafeBoxError):
            cc.decrypt_bytes(blob)
        with self.assertRaises(cc.SafeBoxError):
            cc.decrypt_bytes(blob, password=self.password, key=cc.generate_key())

    def test_encrypt_without_secret(self):
        with self.assertRaises(cc.SafeBoxError):
            cc.encrypt_bytes(self.data)
        with self.assertRaises(cc.SafeBoxError):
            cc.encrypt_bytes(self.data, password="x", key=cc.generate_key())

    def test_not_our_format(self):
        plain = b"this is just a normal file, not encrypted"
        with self.assertRaises(cc.InvalidFileError):
            cc.decrypt_bytes(plain, password=self.password)
        with self.assertRaises(cc.InvalidFileError):
            cc.inspect_blob(plain)
        with self.assertRaises(cc.InvalidFileError):
            cc.decrypt_bytes(b"SBOX" + b"\x00" * 10, password=self.password)

    def test_unsupported_version(self):
        import struct
        header = cc._HEADER_STRUCT.pack(cc.MAGIC, 99, cc.KDF_PBKDF2, 600_000,
                                        b"\x00" * 4, os.urandom(16))
        with self.assertRaises(cc.InvalidFileError):
            cc.decrypt_bytes(header + os.urandom(100), password=self.password)

    def test_tampered_data_detected(self):
        blob = bytearray(cc.encrypt_bytes(self.data, password=self.password))
        blob[-20] ^= 0xFF  # قلب بتات في النص المشفّر
        with self.assertRaises(cc.CorruptedFileError):
            cc.decrypt_bytes(bytes(blob), password=self.password)

    def test_tampered_header_detected(self):
        blob = bytearray(cc.encrypt_bytes(self.data, password=self.password, preset="fast"))
        blob[6] ^= 0x01  # تغيير عدد التكرارات في الترويسة (TAG/AAD يكتشفه)
        with self.assertRaises(cc.SafeBoxError):
            cc.decrypt_bytes(bytes(blob), password=self.password)

    def test_truncated_file(self):
        blob = cc.encrypt_bytes(self.data, password=self.password)
        with self.assertRaises(cc.CorruptedFileError):
            cc.decrypt_bytes(blob[:40], password=self.password)

    def test_empty_data_rejected(self):
        with self.assertRaises(cc.SafeBoxError):
            cc.encrypt_bytes(b"", password=self.password)

    def test_bad_key_length(self):
        with self.assertRaises(cc.SafeBoxError):
            cc.decrypt_bytes(cc.encrypt_bytes(self.data, key=cc.generate_key()), key=b"short")
        with self.assertRaises(cc.SafeBoxError):
            cc.encrypt_bytes(self.data, key=b"short")

    def test_iterations_out_of_range(self):
        with self.assertRaises(cc.SafeBoxError):
            cc.encrypt_bytes(self.data, password=self.password, iterations=5)
        with self.assertRaises(cc.SafeBoxError):
            cc.encrypt_bytes(self.data, password=self.password, preset="nonexistent")


class HelpersTests(unittest.TestCase):
    def test_output_name(self):
        self.assertEqual(cc.output_name("report.pdf", True), "report.pdf.sbox")
        self.assertEqual(cc.output_name("report.pdf.sbox", False), "report.pdf")
        self.assertEqual(cc.output_name("صور.PNG", True), "صور.PNG.sbox")
        self.assertEqual(cc.output_name("../etc/passwd", True), "passwd.sbox")

    def test_key_fingerprint_stable(self):
        key = cc.generate_key()
        self.assertEqual(cc.key_fingerprint(key), cc.key_fingerprint(key))
        self.assertEqual(len(cc.key_fingerprint(key)), 8)

    def test_inspect_blob_info(self):
        blob = cc.encrypt_bytes(b"hello world", password="pw-قوية-جداً-1234", preset="fast")
        info = cc.inspect_blob(blob)
        self.assertTrue(info.encrypted)
        self.assertEqual(info.algorithm, "AES-256-GCM")
        self.assertEqual(info.kdf, "PBKDF2-HMAC-SHA256")
        self.assertEqual(info.iterations, 100_000)
        self.assertEqual(info.encrypted_size, len(blob))

    def test_strength_levels(self):
        self.assertLessEqual(estimate_strength("123456").score, 1)
        self.assertLessEqual(estimate_strength("password").score, 1)
        self.assertGreaterEqual(estimate_strength("Xk9#mQ2vLp7$Wz4!Rt8^Bn6&").score, 4)
        self.assertTrue(estimate_strength("").weak)

    def test_strength_suggestions(self):
        self.assertTrue(estimate_strength("abcdefgh").suggestions)
        self.assertTrue(all(estimate_strength("Xk9#mQ2vLp7$Wz4!Rt8^Bn6&").suggestions))
        arabic = estimate_strength("كلمةمرورطويلةجداوقوية2026!!")
        self.assertGreater(arabic.bits, 60)

    def test_normalize_iterations_bounds(self):
        self.assertEqual(cc._normalize_iterations(None, None), cc.DEFAULT_ITERATIONS)
        self.assertEqual(cc._normalize_iterations(None, "paranoid"), 1_200_000)


if __name__ == "__main__":
    unittest.main(verbosity=2)
