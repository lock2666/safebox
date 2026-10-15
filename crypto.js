/*!
 * crypto.js — محرك تشفير «الخزنة» للمتصفح (Web Crypto API).
 * نفس صيغة ملفات نسخة Python بالضبط، فالملفات متوافقة في الاتجاهين:
 *
 *   SBOX | VERSION | KDF | ITERATIONS | KEY_CHECK | SALT | NONCE | CIPHERTEXT+Tag
 *     4B |    1B   |  1B |     4B     |     4B    | 16B  |  12B  |   AES-256-GCM
 */
(() => {
  "use strict";

  const MAGIC = new Uint8Array([0x53, 0x42, 0x4f, 0x58]); // "SBOX"
  const VERSION = 1;
  const KDF_PBKDF2 = 0;
  const KDF_RAW_KEY = 1;

  const SALT_SIZE = 16;
  const NONCE_SIZE = 12;
  const KEY_SIZE = 32;
  const CHECK_SIZE = 4;
  const HEADER_SIZE = 30;

  const DEFAULT_ITERATIONS = 600000;
  const ITERATION_PRESETS = { fast: 100000, balanced: 600000, paranoid: 1200000 };

  const MAX_FILE_SIZE = 64 * 1024 * 1024;
  const MAX_TEXT_BYTES = 64 * 1024;
  const MAX_PASSWORD_LENGTH = 512;

  const enc = new TextEncoder();
  const dec = new TextDecoder();

  /* ----------------------------------------------------------------- الأخطاء */
  class SafeBoxError extends Error {}
  class InvalidFileError extends SafeBoxError {}
  class WrongKeyError extends SafeBoxError {}
  class CorruptedFileError extends SafeBoxError {}

  const toBytes = (data) => {
    if (data instanceof Uint8Array) return data;
    if (data instanceof ArrayBuffer) return new Uint8Array(data);
    if (ArrayBuffer.isView(data)) return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
    if (typeof data === "string") return enc.encode(data);
    if (Array.isArray(data)) return new Uint8Array(data);
    throw new SafeBoxError("نوع بيانات غير مدعوم (المتوقع: بايتات أو نص).");
  };

  /** يقرأ UInt32 big-endian مع أخذ byteOffset في الحسبان. */
  const readU32 = (bytes, offset) =>
    new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint32(offset, false);

  const writeU32 = (bytes, offset, value) =>
    new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).setUint32(offset, value, false);

  const bytesToHex = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");

  function requireCrypto() {
    if (!(window.crypto && crypto.subtle)) {
      throw new SafeBoxError(
        "متصفحك لا يدعم Web Crypto. افتح الموقع عبر HTTPS (أو localhost) في متصفح حديث."
      );
    }
  }

  /* ------------------------------------------------------------- أدوات مساعدة */
  const generateSalt = () => crypto.getRandomValues(new Uint8Array(SALT_SIZE));
  const generateNonce = () => crypto.getRandomValues(new Uint8Array(NONCE_SIZE));

  async function sha256(data) {
    return new Uint8Array(await crypto.subtle.digest("SHA-256", toBytes(data)));
  }

  async function keyCheckOf(rawKey) {
    const digest = await sha256(rawKey);
    return digest.slice(0, CHECK_SIZE);
  }

  function buildHeader(kdfId, iterations, check, salt) {
    const header = new Uint8Array(HEADER_SIZE);
    header.set(MAGIC, 0);
    header[4] = VERSION;
    header[5] = kdfId;
    new DataView(header.buffer).setUint32(6, iterations, false);
    header.set(check, 10);
    header.set(salt, 14);
    return header;
  }

  function parseHeader(blob) {
    if (blob.length < HEADER_SIZE) {
      throw new InvalidFileError("الملف صغير جداً ولا يحتوي على ترويسة صالحة.");
    }
    for (let i = 0; i < 4; i += 1) {
      if (blob[i] !== MAGIC[i]) {
        throw new InvalidFileError("هذا الملف لم يُشفَّر بواسطة «الخزنة» (ترويسة غير معروفة).");
      }
    }
    const version = blob[4];
    if (version !== VERSION) {
      throw new InvalidFileError(`إصدار الملف (${version}) غير مدعوم من هذه النسخة.`);
    }
    const kdfId = blob[5];
    if (kdfId !== KDF_PBKDF2 && kdfId !== KDF_RAW_KEY) {
      throw new InvalidFileError("خوارزمية اشتقاق المفتاح في الملف غير مدعومة.");
    }
    const iterations = readU32(blob, 6);
    if (kdfId === KDF_PBKDF2 && (iterations < 10000 || iterations > 10000000)) {
      throw new InvalidFileError("عدد تكرارات اشتقاق المفتاح في الملف غير منطقي.");
    }
    const check = blob.slice(10, 14);
    const salt = blob.slice(14, 30);
    return { kdfId, iterations, check, salt, headerSize: HEADER_SIZE };
  }

  const constantTimeEqual = (a, b) => {
    if (a.length !== b.length) return false;
    let diff = 0;
    for (let i = 0; i < a.length; i += 1) diff |= a[i] ^ b[i];
    return diff === 0;
  };

  /* ------------------------------------------------------------ مفاتيح و PBKDF2 */
  async function deriveAesKey(password, salt, iterations) {
    const base = await crypto.subtle.importKey(
      "raw", enc.encode(password), "PBKDF2", false, ["deriveKey", "deriveBits"]);
    return crypto.subtle.deriveKey(
      { name: "PBKDF2", salt: toBytes(salt), iterations, hash: "SHA-256" },
      base,
      { name: "AES-GCM", length: KEY_SIZE * 8 },
      true, // قابلي للاستخراج مطلوبة لحساب بصمة التحقق فقط (يبقى في الذاكرة)
      ["encrypt", "decrypt"]
    );
  }

  function importRawKey(rawKey) {
    return crypto.subtle.importKey(
      "raw", toBytes(rawKey), "AES-GCM", true, ["encrypt", "decrypt"]);
  }

  function generateKeyBytes(length = 32) {
    const size = Math.max(16, Math.min(64, Number(length) || 32));
    return crypto.getRandomValues(new Uint8Array(size));
  }

  /* ------------------------------------------------------- ملفات المفاتيح النصية */
  function base64ToBytes(input) {
    const clean = String(input)
      .trim()
      .replace(/\s+/g, "")          // ناس وأسطر جديدة
      .replace(/-/g, "+")            // URL-safe -> قياسي
      .replace(/_/g, "/");
    if (!clean) throw new SafeBoxError("النص المُدخل ليس Base64 صالحاً.");
    if (!/^[A-Za-z0-9+/]+={0,2}$/.test(clean)) {
      throw new SafeBoxError("النص المُدخل ليس Base64 صالحاً.");
    }
    const padded = clean + "=".repeat((4 - (clean.length % 4)) % 4);
    let binary;
    try {
      binary = atob(padded);
    } catch (_err) {
      throw new SafeBoxError("النص المُدخل ليس Base64 صالحاً.");
    }
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
    return bytes;
  }

  function hexToBytes(text) {
    if (text.length % 2 !== 0 || /[^0-9a-fA-F]/.test(text)) {
      throw new SafeBoxError("ملف المفتاح غير صالح (تنسيق غير مفهوم).");
    }
    const bytes = new Uint8Array(text.length / 2);
    for (let i = 0; i < bytes.length; i += 1) {
      bytes[i] = parseInt(text.slice(i * 2, i * 2 + 2), 16);
    }
    return bytes;
  }

  /**
   * يستخرج مفتاحاً من محتوى ملف .key.
   * يقبل: 32 بايت خام (ثنائي) أو نص Base64/hex مع تعليقات وأسطر فارغة.
   */
  function parseKeyBlob(raw) {
    if (raw instanceof Uint8Array || raw instanceof ArrayBuffer || ArrayBuffer.isView(raw)) {
      const bytes = toBytes(raw);
      if (bytes.length === KEY_SIZE) return bytes;          // مفتاح خام (مثل openssl rand 32)
      raw = String.fromCharCode(...bytes.subarray(0, 8192)); // قد يكون ملفاً نصياً
    } else if (typeof raw !== "string") {
      throw new SafeBoxError("ملف المفتاح غير صالح (نوع غير مدعوم).");
    }
    const text = String(raw);
    const tokens = [];
    for (const line of text.split(/\r?\n/)) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith("#")) continue;
      tokens.push(...trimmed.split(/\s+/));
    }
    const decoded = [];
    for (const token of tokens) {
      let bytes;
      try {
        bytes = token.length === 64 ? hexToBytes(token) : base64ToBytes(token);
      } catch (_err) {
        continue;
      }
      if (bytes.length === KEY_SIZE) return bytes;
      decoded.push(bytes);
    }
    if (decoded.length) return decoded[0];
    throw new SafeBoxError("ملف المفتاح غير صالح (تنسيق غير مفهوم أو ملف فارغ).");
  }

  function coerceKey(input) {
    if (input instanceof Uint8Array) {
      if (input.length === KEY_SIZE) return input;
      throw new SafeBoxError(keyLengthError(input.length));
    }
    if (input instanceof ArrayBuffer) return coerceKey(new Uint8Array(input));
    if (typeof input !== "string") {
      throw new SafeBoxError("نوع المفتاح غير مدعوم — مرّر بايتات أو نصاً.");
    }
    const parsed = parseKeyBlob(input);
    if (parsed.length !== KEY_SIZE) throw new SafeBoxError(keyLengthError(parsed.length));
    return parsed;
  }

  function keyLengthError(length) {
    return `طول المفتاح يجب أن يكون ${KEY_SIZE} بايت (256 بت)، وطول المفتاح المُعطى ${length} بايت.`;
  }

  function normalizeIterations(iterations, preset) {
    if (preset) {
      const value = ITERATION_PRESETS[preset];
      if (!value) throw new SafeBoxError(`إعداد جهد غير معروف: ${prettyPreset(preset)}`);
      return value;
    }
    if (iterations == null) return DEFAULT_ITERATIONS;
    const value = Number(iterations);
    if (!Number.isInteger(value) || value < 10000 || value > 10000000) {
      throw new SafeBoxError("عدد التكرارات يجب أن يكون بين 10,000 و 10,000,000.");
    }
    return value;
  }

  const prettyPreset = (name) => ({ fast: "سريع", balanced: "متوازن", paranoid: "فائق" }[name] || name);

  /* ------------------------------------------------------------------ التشفير */
  async function encryptBytes(data, options = {}) {
    requireCrypto();
    const { password, key, iterations, preset, filename, hideName } = options;
    data = toBytes(data);

    if (!data.length) throw new SafeBoxError("لا يمكن تشفير ملف فارغ.");
    if ((password == null) === (key == null)) {
      throw new SafeBoxError("يجب تحديد كلمة مرور أو ملف مفتاح (واحدة فقط).");
    }
    if (password != null) {
      if (typeof password !== "string" || !password.trim()) {
        throw new SafeBoxError("كلمة المرور مطلوبة.");
      }
      if (password.length > MAX_PASSWORD_LENGTH) throw new SafeBoxError("كلمة المرور طويلة جداً.");
    }
    if (key != null) {
      try {
        coerceKey(key);
      } catch (err) {
        throw new SafeBoxError(`ملف المفتاح غير صالح: ${err.message}`);
      }
    }

    let kdfId, salt, iterationsToUse, aesKey, keyBytes;
    if (key != null) {
      keyBytes = coerceKey(key);
      kdfId = KDF_RAW_KEY;
      iterationsToUse = 0;
      salt = generateSalt();
      aesKey = await importRawKey(keyBytes);
    } else {
      kdfId = KDF_PBKDF2;
      iterationsToUse = normalizeIterations(iterations, preset);
      salt = generateSalt();
      aesKey = await deriveAesKey(password, salt, iterationsToUse);
      keyBytes = new Uint8Array(
        await crypto.subtle.exportKey("raw", aesKey)
      );
    }

    const check = (await keyCheckOf(keyBytes)).slice(0, CHECK_SIZE);
    const header = buildHeader(kdfId, iterationsToUse, check, salt);
    const nonce = generateNonce();

    const meta = {
      name: hideName ? "encrypted" : (filename || "file.bin"),
      size: data.length,
      encrypted_at: new Date().toISOString().slice(0, 19) + "Z",
      tool: "SafeBox/1",
    };
    const metaJson = enc.encode(JSON.stringify(meta));
    const payload = new Uint8Array(4 + metaJson.length + data.length);
    writeU32(payload, 0, metaJson.length);
    payload.set(metaJson, 4);
    payload.set(data, 4 + metaJson.length);

    const cipher = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: nonce, additionalData: header, tagLength: 128 },
      aesKey,
      payload
    );

    const out = new Uint8Array(HEADER_SIZE + NONCE_SIZE + cipher.byteLength);
    out.set(header, 0);
    out.set(nonce, HEADER_SIZE);
    out.set(new Uint8Array(cipher), HEADER_SIZE + NONCE_SIZE);
    return out;
  }

  async function decryptBytes(blob, options = {}) {
    requireCrypto();
    const { password, key } = options;
    if ((password == null) === (key == null)) {
      throw new SafeBoxError("يجب تحديد كلمة المرور أو ملف المفتاح (واحدة فقط).");
    }
    if (password != null && (typeof password !== "string" || !password.trim())) {
      throw new SafeBoxError("كلمة المرور مطلوبة.");
    }
    blob = toBytes(blob);
    const info = parseHeader(blob);

    if (blob.length < info.headerSize + NONCE_SIZE + 16) {
      throw new CorruptedFileError("الملف مقطوع أو ناقص (لا توجد بيانات مشفّرة كاملة).");
    }

    const nonce = blob.slice(info.headerSize, info.headerSize + NONCE_SIZE);
    const cipher = blob.slice(info.headerSize + NONCE_SIZE);
    const header = blob.slice(0, info.headerSize);

    let aesKey, keyBytes;
    if (key != null) {
      keyBytes = coerceKey(key);
      if (info.kdfId === KDF_PBKDF2) {
        throw new WrongKeyError("هذا الملف مُشفَّر بكلمة مرور، وليس بملف مفتاح.");
      }
      aesKey = await importRawKey(keyBytes);
    } else {
      if (info.kdfId === KDF_RAW_KEY) {
        throw new WrongKeyError("هذا الملف مُشفَّر بملف مفتاح، وليس بكلمة مرور.");
      }
      aesKey = await deriveAesKey(password, info.salt, info.iterations);
      keyBytes = new Uint8Array(await crypto.subtle.exportKey("raw", aesKey));
    }

    const actualCheck = (await keyCheckOf(keyBytes)).slice(0, CHECK_SIZE);
    if (!constantTimeEqual(actualCheck, info.check)) {
      throw new WrongKeyError("كلمة المرور أو ملف المفتاح غير صحيح.");
    }

    let payload;
    try {
      payload = new Uint8Array(await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: nonce, additionalData: header, tagLength: 128 },
        aesKey,
        cipher
      ));
    } catch (_err) {
      throw new CorruptedFileError("فشل التحقق من سلامة البيانات: الملف تالف أو تم تعديله.");
    }

    if (payload.length < 4) throw new CorruptedFileError("البيانات المفكوكة غير مكتملة.");
    const metaLength = readU32(payload, 0);
    if (4 + metaLength > payload.length) {
      throw new CorruptedFileError("ترويسة البيانات الوصفية تالفة.");
    }

    let meta = {};
    try {
      meta = JSON.parse(dec.decode(payload.slice(4, 4 + metaLength)));
    } catch (_err) {
      throw new CorruptedFileError("تعذّر قراءة البيانات الوصفية للملف.");
    }
    const data = payload.slice(4 + metaLength);
    return { data, name: String(meta.name || "decrypted.bin"), meta };
  }

  /* --------------------------------------------------------------- النصوص وفحص */
  function bytesToBase64(bytes) {
    let binary = "";
    const chunk = 0x8000;
    for (let i = 0; i < bytes.length; i += chunk) {
      binary += String.fromCharCode(...bytes.subarray(i, i + chunk));
    }
    return btoa(binary);
  }

  async function encryptText(text, options = {}) {
    const blob = await encryptBytes(enc.encode(text), {
      ...options, filename: "text.txt",
    });
    return bytesToBase64(blob);
  }

  async function decryptText(token, options = {}) {
    const blob = base64ToBytes(String(token).trim());
    const result = await decryptBytes(blob, options);
    return dec.decode(result.data);
  }

  function inspectBlob(blob) {
    const info = parseHeader(toBytes(blob));
    return {
      encrypted: true,
      algorithm: "AES-256-GCM",
      kdf: info.kdfId === KDF_PBKDF2 ? "PBKDF2-HMAC-SHA256" : "مفتاح مباشر (ملف مفتاح)",
      iterations: info.iterations,
      key_check: bytesToHex(info.check),
      salt: bytesToBase64(info.salt),
      encrypted_size: blob.length,
    };
  }

  function outputName(filename, encrypted) {
    const base = String(filename || "file").replace(/\\/g, "/").split("/").pop() || "file";
    if (encrypted) return base.toLowerCase().endsWith(".sbox") ? base : `${base}.sbox`;
    if (!base.toLowerCase().endsWith(".sbox")) return `${base}.decrypted`;
    return base.slice(0, -5) || "decrypted";
  }

  /* -------------------------------------------------------------------- التصدير */
  window.SafeBoxCrypto = {
    MAGIC_TEXT: "SBOX",
    VERSION,
    HEADER_SIZE,
    ITERATION_PRESETS,
    DEFAULT_ITERATIONS,
    MAX_FILE_SIZE,
    MAX_TEXT_BYTES,
    MAX_PASSWORD_LENGTH,
    SafeBoxError, InvalidFileError, WrongKeyError, CorruptedFileError,
    encryptBytes, decryptBytes, encryptText, decryptText,
    inspectBlob, outputName, parseKeyBlob, coerceKey, generateKeyBytes,
    bytesToBase64, base64ToBytes, requireCrypto,
  };
})();
