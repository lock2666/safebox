"""تقدير قوة كلمة المرور — يُستخدم في الواجهة وفي التحقق من الخادم."""

from __future__ import annotations

import math
from dataclasses import dataclass, field

# قائمة مختصرة من كلمات المرور الشائعة (للاستخدام المحلي فقط)
COMMON_PASSWORDS = {
    "123456", "123456789", "12345678", "12345", "1234567", "password", "password1",
    "1234567890", "qwerty", "abc123", "111111", "iloveyou", "admin", "letmein",
    "welcome", "monkey", "dragon", "000000", "sunshine", "princess", "football",
    "starwars", "qwerty123", "passw0rd", "alzaeem", "أحمدرسول", "555555",
}

# (أدنى قيمة bits، التسمية، اللون)
_LEVELS = [
    (60, "قوية جداً", "#22c55e"),
    (48, "قوية", "#4ade80"),
    (36, "جيدة", "#facc15"),
    (28, "متوسطة", "#fb923c"),
    (0, "ضعيفة", "#ef4444"),
]


@dataclass(frozen=True)
class Strength:
    score: int            # 0..4
    level: str
    color: str
    bits: float
    suggestions: list[str] = field(default_factory=list)

    @property
    def weak(self) -> bool:
        return self.score <= 1


def _pool_size(password: str) -> int:
    pool = 0
    if any(c.islower() for c in password):
        pool += 26
    if any(c.isupper() for c in password):
        pool += 26
    if any(c.isdigit() for c in password):
        pool += 10
    if any(not c.isalnum() for c in password):
        pool += 33
    if any(ord(c) > 127 for c in password):
        pool += 500  # تقدير سخي للأبجديات غير اللاتينية (العربية مثلاً)
    return pool


def estimate_strength(password: str) -> Strength:
    """يقيّم قوة كلمة المرور ويعيد النتيجة مع اقتراحات التحسين."""
    if not password:
        return Strength(0, "فارغة", "#64748b", 0.0, ["أدخل كلمة مرور."])

    suggestions: list[str] = []
    pool = _pool_size(password)
    bits = len(password) * math.log2(pool) if pool > 1 else 0.0

    lowered = password.lower()
    if lowered in COMMON_PASSWORDS:
        return Strength(0, "ضعيفة جداً", "#ef4444", 8.0,
                        ["هذه من أشهر كلمات المرور المخترقة — لا تستخدمها أبداً."])
    if any(password.lower().startswith(common) or common in password.lower()
           for common in COMMON_PASSWORDS):
        suggestions.append("تتضمن كلمة مرور شائعة — تجنّبها.")

    # أنماط متكررة
    if len(set(password)) <= 2:
        suggestions.append("تستخدم حرفين فقط متكررين — تنويع أكبر.")
    if password.isdigit():
        suggestions.append("أرقام فقط — أضف حروفاً ورموزاً.")
    if password.isalpha():
        suggestions.append("حروف فقط — أضف أرقاماً ورموزاً.")
    if any(password[i:i + 3] == password[i + 1:i + 4] == password[i + 2:i + 5]
           for i in range(len(password) - 2)):
        suggestions.append("توجد تكرارات متتالية (aaa, 123).")

    for pattern, label in (
        ("0123456789", "أرقاماً متسلسلة"),
        ("abcdefghijklmnopqrstuvwxyz", "حروفاً متسلسلة"),
        ("qwertyuiop", "صفاً من لوحة المفاتيح"),
    ):
        if pattern[:6] in lowered:
            suggestions.append(f"تتضمن {label} — تجنّب التسلسل.")

    if len(password) < 12:
        suggestions.append("الطول الأفضل 16 حرفاً على الأقل.")
    if not any(c.isupper() for c in password) or not any(c.islower() for c in password):
        suggestions.append("اخلط بين الأحرف الكبيرة والصغيرة.")

    score = 0
    for idx, (min_bits, _label, _color) in enumerate(_LEVELS):
        if bits >= min_bits:
            score = len(_LEVELS) - 1 - idx
            break

    if len(password) >= 16 and len(set(password)) >= 10:
        score = min(4, score + 1)

    # خصم على الأنماط الضعيفة
    if suggestions:
        score = max(0, score - 1)

    label, color = _LEVELS[len(_LEVELS) - 1 - score][1], _LEVELS[len(_LEVELS) - 1 - score][2]
    if not suggestions:
        suggestions.append("لا اقتراحات — كلمة مرور ممتازة.")
    return Strength(score, label, color, round(bits, 1), suggestions)


def generate_readable_password(length: int = 20) -> str:
    """يولّد كلمة مرور عشوائية قوية وقابلة للنسخ."""
    import secrets
    import string

    if length < 8:
        length = 8
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*-_=+?"
    while True:
        pw = "".join(secrets.choice(alphabet) for _ in range(length))
        if (any(c.islower() for c in pw) and any(c.isupper() for c in pw)
                and any(c.isdigit() for c in pw)
                and any(c in "!@#$%^&*-_=+?" for c in pw)):
            return pw
