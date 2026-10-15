"""محرك التشفير لتطبيق «الخزنة» (SafeBox).

تشفير الملفات والنصوص باستخدام AES-256-GCM مع اشتقاق المفتاح عبر PBKDF2-HMAC-SHA256.

صيغة الملف المُشفَّر (كل الحقول big-endian):

    +--------+---------+-------+-----------+-----------+-------+-------+--------------+
    | MAGIC  | VERSION | KDF   | ITERATIONS| KEY_CHECK | SALT  | NONCE | CIPHERTEXT   |
    | 4 بايت | 1 بايت  | 1 بايت|  4 بايت   |  4 بايت   |16 بايت|12 بايت| + الوسم GCM |
    +--------+---------+-------+-----------+-----------+-------+-------+--------------+

النص المُشفَّر داخل CIPHERTEXT هو:

    meta_len (4 بايت) + meta_json (UTF-8) + البيانات الأصلية

KDF: 0 = PBKDF2-HMAC-SHA256 (كلمة مرور)، 1 = مفتاح مباشر (ملف مفتاح).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import math
import os
import struct
from dataclasses import dataclass, field
from datetime import datetime, timezone

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# ---------------------------------------------------------------- ثوابت الصيغة
MAGIC = b"SBOX"
VERSION = 1
KDF_PBKDF2 = 0
KDF_RAW_KEY = 1

SALT_SIZE = 16
NONCE_SIZE = 12
KEY_SIZE = 32          # AES-256
CHECK_SIZE = 4         # بصمة تحقق سريعة من المفتاح

DEFAULT_ITERATIONS = 600_000  # توصية OWASP لـ PBKDF2-SHA256

# خيارات الجهد لمقاومة التخمين (تُخزَّن داخل الملف نفسه)
ITERATION_PRESETS: dict[str, int] = {
    "fast": 100_000,       # سريع، مناسب للملفات الكثيرة
    "balanced": 600_000,   # متوازن (الافتراضي)
    "paranoid": 1_200_000, # أعلى مقاومة، أبطأ قليلاً
}

HEADER_SIZE = 4 + 1 + 1 + 4 + CHECK_SIZE + SALT_SIZE  # = 30 بايت
_HEADER_STRUCT = struct.Struct(">4sBBI4s16s")  # magic, version, kdf, iterations, check, salt


# -------------------------------------------------------------------- الأخطاء
class SafeBoxError(Exception):
    """خطأ أساسي في التطبيق."""


class InvalidFileError(SafeBoxError):
    """الملف ليس بصيغة «الخزنة» (أو إصدار غير مدعوم)."""


class WrongKeyError(SafeBoxError):
    """كلمة المرور أو ملف المفتاح غير صحيح."""


class CorruptedFileError(SafeBoxError):
    """رأس الملف سليم لكن البيانات التالفة/مُعدَّلة (فشل وسم GCM)."""


# ------------------------------------------------------------------- النماذج
@dataclass(frozen=True)
class Decrypted:
    """نتيجة فك التشفير."""

    data: bytes
    name: str = "decrypted.bin"
    meta: dict = field(default_factory=dict)


@dataclass(frozen=True)
class BlobInfo:
    """معلومات يمكن قراءتها من رأس الملف بدون مفتاح."""

    encrypted: bool = True
    algorithm: str = "AES-256-GCM"
    kdf: str = ""
    iterations: int = 0
    key_check: str = ""       # بصمة المفتاح المقصودة (hex)
    salt: str = ""            # hex
    encrypted_size: int = 0
    created_at: str | None = None
    original_name: str | None = None
    original_size: int | None = None


# ----------------------------------------------------------- أدوات مساعدة
def generate_key() -> bytes:
    """يولّد مفتاح AES-256 عشوائياً (32 بايت)."""
    return AESGCM.generate_key(bit_length=256)


def generate_salt() -> bytes:
    return os.urandom(SALT_SIZE)


def generate_nonce() -> bytes:
    return os.urandom(NONCE_SIZE)


def key_fingerprint(key: bytes) -> str:
    """بصمة قصيرة للمفتاح تساعد المستخدم على التمييز بين المفاتيح."""
    return hashlib.sha256(key).hexdigest()[:CHECK_SIZE * 2]


def _normalize_iterations(iterations, preset: str | None = None) -> int:
    if preset:
        try:
            return ITERATION_PRESETS[preset]
        except KeyError:
            raise SafeBoxError(f"إعداد جهد غير معروف: {preset}") from None
    if iterations is None:
        return DEFAULT_ITERATIONS
    iterations = int(iterations)
    if not 10_000 <= iterations <= 10_000_000:
        raise SafeBoxError("عدد التكرارات يجب أن يكون بين 10,000 و 10,000,000.")
    return iterations


def derive_key(password: str, salt: bytes, iterations: int) -> bytes:
    """يشتق مفتاح 256 بت من كلمة المرور عبر PBKDF2-HMAC-SHA256."""
    if not isinstance(password, str) or not password:
        raise SafeBoxError("كلمة المرور مطلوبة.")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(password.encode("utf-8"))


def _decode_key_token(token: str) -> bytes:
    """يفسّر نصاً واحداً كمفتاح: hex (64 محرفاً) أو Base64."""
    token = token.strip()
    if len(token) == 64 and all(c in "0123456789abcdefABCDEF" for c in token):
        return bytes.fromhex(token)
    try:
        key_bytes = base64.urlsafe_b64decode(token + "=" * (-len(token) % 4))
    except Exception:
        return b""
    return key_bytes


def _parse_key_blob(raw: bytes) -> bytes:
    """يستخرج المفتاح من محتوى نصي (يتجاهل التعليقات والأسطر الفارغة)."""
    text = raw.decode("utf-8", errors="ignore")
    tokens: list[str] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        tokens.extend(line.split())

    decoded: list[bytes] = []
    for token in tokens:
        key_bytes = _decode_key_token(token)
        if not key_bytes:
            continue
        if len(key_bytes) == KEY_SIZE:
            return key_bytes
        decoded.append(key_bytes)

    if decoded:
        return decoded[0]  # سيُرفض لاحقاً بسبب طوله الخاطئ برسالة واضحة
    raise SafeBoxError("ملف المفتاح غير صالح (تنسيق غير مفهوم أو ملف فارغ).")


def _coerce_key(key) -> bytes:
    """يقبل مفتاحاً كـ bytes خام أو كنص base64/hex (كما في ملف المفتاح)."""
    if isinstance(key, (bytes, bytearray)):
        raw = bytes(key)
        key_bytes = raw if len(raw) == KEY_SIZE else _parse_key_blob(raw)
    elif isinstance(key, str):
        key_bytes = _parse_key_blob(key.encode("utf-8"))
    else:
        raise SafeBoxError("نوع المفتاح غير مدعوم.")

    if len(key_bytes) != KEY_SIZE:
        raise SafeBoxError(
            f"طول المفتاح يجب أن يكون {KEY_SIZE} بايت (256 بت)، وطول المفتاح المُعطى {len(key_bytes)} بايت."
        )
    return key_bytes


def _build_header(iterations: int, check: bytes, salt: bytes) -> bytes:
    kdf_id = KDF_PBKDF2 if iterations > 0 else KDF_RAW_KEY
    return _HEADER_STRUCT.pack(MAGIC, VERSION, kdf_id, iterations, check, salt)


def _parse_header(blob: bytes) -> tuple[int, int, bytes, bytes, int]:
    """يعيد (kdf_id, iterations, check, salt, offset_before_nonce)."""
    if len(blob) < HEADER_SIZE:
        raise InvalidFileError("الملف صغير جداً ولا يحتوي على ترويسة صالحة.")
    try:
        magic, version, kdf_id, iterations, check, salt = _HEADER_STRUCT.unpack_from(blob, 0)
    except struct.error as exc:
        raise InvalidFileError("ترويسة الملف تالفة.") from exc

    if magic != MAGIC:
        raise InvalidFileError("هذا الملف لم يُشفَّر بواسطة «الخزنة» (ترويسة غير معروفة).")
    if version != VERSION:
        raise InvalidFileError(f"إصدار الملف ({version}) غير مدعوم من هذه النسخة.")
    if kdf_id not in (KDF_PBKDF2, KDF_RAW_KEY):
        raise InvalidFileError("خوارزمية اشتقاق المفتاح في الملف غير مدعومة.")
    if kdf_id == KDF_PBKDF2 and not (10_000 <= iterations <= 10_000_000):
        raise InvalidFileError("عدد تكرارات اشتقاق المفتاح في الملف غير منطقي.")
    return kdf_id, iterations, check, salt, HEADER_SIZE


# ------------------------------------------------------------------- التشفير
def encrypt_bytes(
    data: bytes,
    *,
    password: str | None = None,
    key: bytes | str | None = None,
    iterations: int | None = None,
    preset: str | None = None,
    filename: str | None = None,
    hide_name: bool = False,
) -> bytes:
    """يشفّر بيانات ويعيد الملف الكامل بصيغة «الخزنة»."""
    if not isinstance(data, (bytes, bytearray)):
        raise SafeBoxError("البيانات المراد تشفيرها يجب أن تكون بايتات.")
    data = bytes(data)
    if not data:
        raise SafeBoxError("لا يمكن تشفير ملف فارغ.")

    if (password is None) == (key is None):
        raise SafeBoxError("يجب تحديد كلمة مرور أو ملف مفتاح (واحدة فقط).")

    salt = generate_salt()
    if key is not None:
        key_bytes = _coerce_key(key)
        iters = 0
    else:
        iters = _normalize_iterations(iterations, preset)
        key_bytes = derive_key(password, salt, iters)

    check = hashlib.sha256(key_bytes).digest()[:CHECK_SIZE]
    header = _build_header(iters, check, salt)
    nonce = generate_nonce()

    meta = {
        "name": "encrypted" if hide_name else (filename or "file.bin"),
        "size": len(data),
        "encrypted_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "tool": "SafeBox/1",
    }
    meta_json = json.dumps(meta, ensure_ascii=False).encode("utf-8")

    payload = struct.pack(">I", len(meta_json)) + meta_json + data
    ciphertext = AESGCM(key_bytes).encrypt(nonce, payload, header)  # type: ignore[arg-type]

    return header + nonce + ciphertext


def decrypt_bytes(
    blob: bytes, *, password: str | None = None, key: bytes | str | None = None
) -> Decrypted:
    """يفك تشفير ملف بصيغة «الخزنة» ويتحقق من سلامته."""
    if (password is None) == (key is None):
        raise SafeBoxError("يجب تحديد كلمة المرور أو ملف المفتاح (واحدة فقط).")

    kdf_id, iterations, check, salt, offset = _parse_header(blob)
    if len(blob) < offset + NONCE_SIZE + 16:
        raise CorruptedFileError("الملف مقطوع أو ناقص (لا توجد بيانات مشفّرة كاملة).")
    nonce = blob[offset:offset + NONCE_SIZE]
    ciphertext = blob[offset + NONCE_SIZE:]
    header = blob[:offset]

    if key is not None:
        key_bytes = _coerce_key(key)
        if kdf_id == KDF_PBKDF2:
            raise WrongKeyError("هذا الملف مُشفَّر بكلمة مرور، وليس بملف مفتاح.")
    else:
        if kdf_id == KDF_RAW_KEY:
            raise WrongKeyError("هذا الملف مُشفَّر بملف مفتاح، وليس بكلمة مرور.")
        key_bytes = derive_key(password, salt, iterations)

    # تحقق سريع (ثابت الزمن) لتحديد إن كان المفتاح خاطئاً قبل فك التشفير
    actual_check = hashlib.sha256(key_bytes).digest()[:CHECK_SIZE]
    if not hmac.compare_digest(actual_check, check):
        raise WrongKeyError("كلمة المرور أو ملف المفتاح غير صحيح.")

    try:
        payload = AESGCM(key_bytes).decrypt(nonce, ciphertext, header)
    except InvalidTag as exc:
        raise CorruptedFileError(
            "فشل التحقق من سلامة البيانات: الملف تالف أو تم تعديله."
        ) from exc

    if len(payload) < 4:
        raise CorruptedFileError("البيانات المفكوكة غير مكتملة.")
    (meta_len,) = struct.unpack_from(">I", payload, 0)
    if 4 + meta_len > len(payload):
        raise CorruptedFileError("ترويسة البيانات الوصفية تالفة.")

    try:
        meta = json.loads(payload[4:4 + meta_len].decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CorruptedFileError("تعذّر قراءة البيانات الوصفية للملف.") from exc

    data = payload[4 + meta_len:]
    name = str(meta.get("name") or "decrypted.bin")
    return Decrypted(data=data, name=name, meta=meta)


# ------------------------------------------------ تشفير النصوص وفك تشفيرها
def encrypt_text(
    text: str, *, password: str | None = None, key: bytes | str | None = None,
    preset: str | None = None, iterations: int | None = None,
) -> str:
    """يشفّر نصاً ويعيده نصاً Base64 جاهزاً للنسخ."""
    blob = encrypt_bytes(
        text.encode("utf-8"),
        password=password, key=key, preset=preset, iterations=iterations,
        filename="text.txt",
    )
    return base64.urlsafe_b64encode(blob).decode("ascii")


def decrypt_text(
    token: str, *, password: str | None = None, key: bytes | str | None = None
) -> str:
    """يفك تشفير نص Base64 أنتجه encrypt_text."""
    raw = token.strip()
    try:
        blob = base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))
    except Exception as exc:
        raise InvalidFileError("النص المُدخل ليس Base64 صالحاً.") from exc
    return decrypt_bytes(blob, password=password, key=key).data.decode("utf-8")


def inspect_blob(blob: bytes) -> BlobInfo:
    """يقرأ معلومات الملف من ترويسته فقط (بدون مفتاح، وبدون فك التشفير)."""
    kdf_id, iterations, check, salt, offset = _parse_header(blob)

    info = BlobInfo(
        algorithm="AES-256-GCM",
        kdf="PBKDF2-HMAC-SHA256" if kdf_id == KDF_PBKDF2 else "مفتاح مباشر (ملف مفتاح)",
        iterations=iterations,
        key_check=check.hex(),
        salt=salt.hex(),
        encrypted_size=len(blob),
    )

    # محاولة استخراج الحجم الأصلي من طول النص المشفّر دون كسر التشفير:
    # لا يمكن قراءة الـ meta بدون المفتاح، لذا نكتفي بحجم الملف.
    return info


def output_name(filename: str, encrypted: bool) -> str:
    """اسم الملف الناتج للتنزيل."""
    base = os.path.basename(filename or "file").strip() or "file"
    if encrypted:
        if base.lower().endswith(".sbox"):
            return base
        return f"{base}.sbox"
    if base.lower().endswith(".sbox"):
        return base[:-5] or "decrypted"
    return f"{base}.decrypted"


def estimate_entropy_bits(password: str) -> float:
    """تقدير بسيط لعشوائية كلمة المرور (bits)."""
    if not password:
        return 0.0
    pool = 0
    classes = {
        "lower": any(c.islower() for c in password),
        "upper": any(c.isupper() for c in password),
        "digit": any(c.isdigit() for c in password),
        "symbol": any(not c.isalnum() for c in password),
    }
    if classes["lower"]:
        pool += 26
    if classes["upper"]:
        pool += 26
    if classes["digit"]:
        pool += 10
    if classes["symbol"]:
        pool += 33
    non_ascii = sum(1 for c in password if ord(c) > 127)
    pool += non_ascii * 50  # تقدير سخي للأحرف العربية مثلاً
    return len(password) * math.log2(pool) if pool > 1 else 0.0
