#!/usr/bin/env python3
"""أداة سطر الأوامر لتطبيق «الخزنة» — تشفير وفك تشفير الملفات بدون متصفح.

أمثلة:
    python cli.py encrypt secret.pdf -p "كلمة-المرور"
    python cli.py decrypt secret.pdf.sbox -p "كلمة-المرور" -o restored.pdf
    python cli.py keygen -o my.key
    python cli.py info secret.pdf.sbox
    python cli.py strength "كلمة-المرور"
"""

from __future__ import annotations

import argparse
import getpass
import os
import sys

import crypto_core as cc
from passwords import estimate_strength


def _read_key_file(path: str) -> bytes:
    with open(path, "rb") as fh:
        return fh.read()


def _resolve_secret(args, *, prompt: str, for_encrypt: bool):
    """يعيد (password, key) حسب الخيارات المُمرَّرة."""
    if args.key_file and args.password:
        raise SystemExit("✋ اختر طريقة واحدة فقط: كلمة مرور (-p) أو ملف مفتاح (-k).")
    if args.key_file:
        return None, _read_key_file(args.key_file)
    password = args.password
    if password is None:
        password = getpass.getpass(prompt + ": ")
    if not password:
        raise SystemExit("✋ كلمة المرور مطلوبة.")
    return password, None


def cmd_encrypt(args) -> int:
    with open(args.file, "rb") as fh:
        data = fh.read()
    password, key = _resolve_secret(args, prompt="كلمة المرور للتشفير", for_encrypt=True)

    blob = cc.encrypt_bytes(
        data, password=password, key=key, preset=args.preset,
        filename=os.path.basename(args.file), hide_name=args.hide_name,
    )
    out = args.output or cc.output_name(args.file, encrypted=True)
    with open(out, "wb") as fh:
        fh.write(blob)

    print(f"✅ تم التشفير: {out}")
    print(f"   الأصلي: {len(data):,} بايت → المشفّر: {len(blob):,} بايت (زيادة {len(blob) - len(data):,})")
    if password:
        s = estimate_strength(password)
        print(f"   قوة كلمة المرور: {s.level} ({s.bits} بت)")
    print("⚠️  احتفظ بكلمة المرور/ملف المفتاح — بدونهما لا يمكن استعادة البيانات.")
    return 0


def cmd_decrypt(args) -> int:
    with open(args.file, "rb") as fh:
        blob = fh.read()
    password, key = _resolve_secret(args, prompt="كلمة المرور لفك التشفير", for_encrypt=False)

    try:
        result = cc.decrypt_bytes(blob, password=password, key=key)
    except cc.SafeBoxError as exc:
        print(f"✋ {exc}", file=sys.stderr)
        return 1

    out = args.output or os.path.basename(result.name)
    with open(out, "wb") as fh:
        fh.write(result.data)
    print(f"✅ تم فك التشفير: {out} ({len(result.data):,} بايت)")
    return 0


def cmd_keygen(args) -> int:
    key = cc.generate_key() if args.length == 32 else os.urandom(args.length)
    out = args.output or "safebox.key"
    with open(out, "w", encoding="utf-8") as fh:
        fh.write("# مفتاح «الخزنة» — لا تشاركه مع أحد واحتفظ بنسخة احتياطية.\n")
        import base64
        fh.write(base64.urlsafe_b64encode(key).decode("ascii") + "\n")
    print(f"✅ تم توليد المفتاح ({len(key) * 8} بت) في: {out}")
    print("⚠️  إن فقدت هذا الملف فلا يمكن فك تشفير ملفاتك أبداً.")
    return 0


def cmd_info(args) -> int:
    with open(args.file, "rb") as fh:
        blob = fh.read()
    try:
        info = cc.inspect_blob(blob)
    except cc.SafeBoxError as exc:
        print(f"✋ {exc}", file=sys.stderr)
        return 1
    print("🔎 معلومات الملف (بدون فك التشفير):")
    print(f"   الخوارزمية : {info.algorithm}")
    print(f"   اشتقاق المفتاح: {info.kdf}")
    print(f"   عدد التكرارات : {info.iterations or '—'}")
    print(f"   بصمة المفتاح  : {info.key_check}")
    print(f"   الحجم المشفّر  : {info.encrypted_size:,} بايت")
    return 0


def cmd_strength(args) -> int:
    s = estimate_strength(args.password)
    print(f"القوة: {s.level} — {s.score}/4 ({s.bits} بت)")
    for tip in s.suggestions:
        print("  • " + tip)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cli.py",
        description="«الخزنة» — تشفير وفك تشفير الملفات (AES-256-GCM + PBKDF2).",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_enc = sub.add_parser("encrypt", help="تشفير ملف")
    p_enc.add_argument("file", help="مسار الملف")
    p_enc.add_argument("-p", "--password", help="كلمة المرور (يُسأل عنها إن لم تُحدَّد)")
    p_enc.add_argument("-k", "--key-file", help="ملف مفتاح بدلاً من كلمة المرور")
    p_enc.add_argument("-o", "--output", help="مسار الملف الناتج")
    p_enc.add_argument("--preset", choices=list(cc.ITERATION_PRESETS), default="balanced",
                       help="قوة مقاومة التخمين")
    p_enc.add_argument("--hide-name", action="store_true", help="إخفاء اسم الملف الأصلي")
    p_enc.set_defaults(func=cmd_encrypt)

    p_dec = sub.add_parser("decrypt", help="فك تشفير ملف")
    p_dec.add_argument("file", help="مسار الملف المشفّر")
    p_dec.add_argument("-p", "--password", help="كلمة المرور")
    p_dec.add_argument("-k", "--key-file", help="ملف المفتاح")
    p_dec.add_argument("-o", "--output", help="مسار الملف المسترجع")
    p_dec.set_defaults(func=cmd_decrypt)

    p_key = sub.add_parser("keygen", help="توليد ملف مفتاح عشوائي")
    p_key.add_argument("-o", "--output", help="مسار ملف المفتاح")
    p_key.add_argument("--length", type=int, default=32, help="طول المفتاح بالبايت (32 افتراضياً)")
    p_key.set_defaults(func=cmd_keygen)

    p_info = sub.add_parser("info", help="معلومات ملف مشفّر بدون كلمة مرور")
    p_info.add_argument("file", help="مسار الملف المشفّر")
    p_info.set_defaults(func=cmd_info)

    p_str = sub.add_parser("strength", help="تقييم قوة كلمة مرور")
    p_str.add_argument("password", help="كلمة المرور")
    p_str.set_defaults(func=cmd_strength)

    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except cc.SafeBoxError as exc:
        print(f"✋ {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nتم الإلغاء.")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
