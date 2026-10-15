# 🔐 الخزنة — نسخة Node.js

تشفير وفك تشفير الملفات من سطر الأوامر باستخدام Node.js **بدون أي حزمة خارجية**
(يعتمد على `node:crypto` و Web Crypto المدمجين). تتطلب Node **18 أو أحدث**.

> ✅ الصيغة مطابقة تماماً لـ Python ونسخة الويب: ما تشفّره هنا يُفتح هناك والعكس.

## 📦 التشغيل

```bash
node node.js --help                 # المساعدة الكاملة
node node.js encrypt report.pdf -p "كلمة-قوية-2026"
node node.js keygen -o my.key --length 32
node node.js decrypt report.pdf.sbox -p "كلمة-قوية-2026"
node node.js decrypt report.pdf.sbox -k my.key -o report.pdf
node node.js info report.pdf.sbox   # فحص بدون كلمة مرور
node node.js text -t "رسالة سرية" -p "كلمة-قوية-2026"
```

## 🧾 الأوامر

| الأمر | الوصف |
|---|---|
| `encrypt <ملف>` | تشفير ملف → `<ملف>.sbox` |
| `decrypt <ملف>` | فك تشفير → يستعيد الاسم الأصلي من داخل الملف |
| `keygen` | توليد ملف مفتاح `.key` (Base64) |
| `info <ملف>` | عرض ترويسة الملف (خوارزمية، تكرارات، بصمة) بدون مفتاح |
| `text -t <نص>` | تشفير نص إلى Base64، أو فكه تلقائياً |

## ⚙️ الخيارات

```
-p, --password <ك>   كلمة المرور (يُطلب تفاعلياً بأمان إن لم تُحدَّد)
-k, --key <ملف>      ملف المفتاح بدلاً من كلمة المرور
-o, --output <مسار>  مسار الملف الناتج
--preset <اسم>       fast (100k) | balanced (600k) | paranoid (1.2M)
--length <بايت>      طول المفتاح عند keygen (32 افتراضياً، 16–64)
-t, --text <نص>      النص لتشفيره/فكه
-f, --force          استبدال الملف الناتج بدون سؤال
-h, --help           المساعدة   |   -V, --version   معلومات الإصدار
-v, --verbose        تفاصيل أكثر (محفوظة للتوسّع)
```

> 💡 يمكن أيضاً تمرير الملف عبر `stdin`: `type secret.txt | node node.js text`

## 🧪 الاختبارات

```bash
node test_node.js        # 35 اختباراً للمحرك + سطر الأوامر
python compat_test.py    # توافق Python ↔ Node.js في الاتجاهين
```

نتيجة آخر تشغيل: **35/35 ناجح** + توافق كامل مع Python (ملفات، مفاتيح، نصوص).

## 📐 صيغة الملف

```
SBOX │VERSION│KDF│ITERATIONS│KEY_CHECK│SALT │NONCE│CIPHERTEXT + Tag
 4B  │  1B   │1B │   4B     │   4B    │16B  │12B  │  AES-256-GCM (16B)
```

- `KDF`: `0 = PBKDF2-HMAC-SHA256` (كلمة مرور) · `1 = مفتاح مباشر` (ملف مفتاح)
- `KEY_CHECK`: أول 4 بايت من `SHA-256(المفتاح)` للتحقق السريع من صحته
- `SALT`/`NONCE`: عشوائيان لكل ملف، فلا يتكرر التشفير أبداً

## 🗂️ الملفات

| الملف | الدور |
|---|---|
| `crypto.js` | محرك التشفير — نفس منطق `crypto_core.py` بصيغة JS |
| `node.js` | واجهة سطر الأوامر |
| `test_node.js` | اختبارات شاملة |
| `compat_test.py` | اختبار التوافق مع نسخة Python |

> `crypto.js` يعمل أيضاً في المتصفح (يُصدّر `window.SafeBoxCrypto` عند وجود `window`).

## ⚠️ أمان

- أقصى حجم ملف: 64 م.بايت · كلمة مرور حتى 512 محرفاً
- كلمة المرور لا تُكتب في أي سجل أو ملف مؤقت
- مقارنة بصمة المفتاح ثابتة الزمن (تمنع تسريب المعلومات بالتوقيت)
- `--force` يستبدل الملفات؛ بدونه يُطلب تأكيد تفاعلي

---

# 🔐 SafeBox — Node.js CLI

Client-side file encryption with Node.js — **zero dependencies** (uses built-in `node:crypto`
and the global Web Crypto API). Requires Node **18+**.

```bash
node node.js encrypt report.pdf -p "strong-passphrase"
node node.js decrypt report.pdf.sbox -p "strong-passphrase"
node node.js keygen -o my.key
node node.js info report.pdf.sbox
```

Algorithm: **AES-256-GCM** with **PBKDF2-HMAC-SHA256** key derivation (100k/600k/1.2M
iterations). Files are byte-for-byte compatible with the Python and web editions.

```bash
node test_node.js      # 35 tests (engine + CLI)
python compat_test.py  # cross-compatibility with the Python edition
```

## File format

```
SBOX │VER│KDF│ITERATIONS│CHECK│SALT │NONCE│CIPHERTEXT+Tag
 4B  │1B │1B │   4B     │ 4B  │16B  │12B  │ AES-256-GCM
```

- `KDF`: `0 = PBKDF2-HMAC-SHA256` (password) · `1 = raw key` (key file)
- `CHECK`: first 4 bytes of `SHA-256(key)` — fast "wrong password" detection
- `SALT`/`NONCE`: random per file, so encrypting the same file twice gives different output

## Options

| Flag | Meaning |
|---|---|
| `-p, --password` | password (prompted securely if omitted) |
| `-k, --key` | key file instead of a password |
| `-o, --output` | output path |
| `--preset` | `fast` / `balanced` / `paranoid` |
| `--length` | key size in bytes for `keygen` (16–64, default 32) |
| `-t, --text` | text to encrypt/decrypt (Base64) |
| `-f, --force` | overwrite output without asking |
| `-h, --help` | help · `-V, --version` version info |

Limits: files up to 64 MB, passwords up to 512 characters, constant-time key check.
