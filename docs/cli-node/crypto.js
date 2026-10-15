/**
 * crypto.js — محرك «الخزنة» لمتصفح الويب (Web Crypto API)
 *
 * نفس صيغة الملفات بالضبط، فالملفات متوافقة في الاتجاهين:
 *   Python (crypto_core.py) ↔ Web (هذا الملف) ↔ Node.js (../cli-node/node.js)
 *
 *     SBOX │ VERSION │ KDF │ ITERATIONS │ KEY_CHECK │ SALT │ NONCE │ CIPHERTEXT+Tag
 *       4B │     1B  │ 1B  │     4B     │     4B    │ 16B  │  12B  │  AES-256-GCM
 */

/* ------------------------------------------------ صيغة الملف --------------- */
const MAGIC = new Uint8Array([0x53, 0x42, 0x4f, 0x58]); // "SBOX"
const VERSION = 1;
const KDF_PBKDF2 = 0;   // كلمة مرور -> PBKDF2-HMAC-SHA256
const KDF_RAW_KEY = 1;  // ملف مفتاح -> المفتاح مستخدم مباشرة
const SALT_SIZE = 16;
const NONCE_SIZE = 12;
const KEY_SIZE = 32;    // AES-256
const CHECK_SIZE = 4;
const HEADER_SIZE = 30;
const TAG_BYTES = 16;

const DEFAULT_ITERATIONS = 600000;   // توصية OWASP لـ PBKDF2-SHA256
const ITERATION_PRESETS = { fast: 100000, balanced: 600000, paranoid: 1200000 };

const MIN_ITERATIONS = 10000;
const MAX_ITERATIONS = 10000000;

/* ------------------------------------------------ حدود الاستخدام ---------- */
const MAX_FILE_SIZE = 64 * 1024 * 1024; // 64 م.بايت
const MAX_TEXT_BYTES = 64 * 1024;       // 64 ك.بايت للنص العادي
const MAX_PASSWORD_LENGTH = 512;

/* ------------------------------------------------ أدوات بايتات ------------ */
const enc = new TextEncoder();
const dec = new TextDecoder();

class SafeBoxError extends Error {}
class InvalidFileError extends SafeBoxError {}
class WrongKeyError extends SafeBoxError {}
class CorruptedFileError extends SafeBoxError {}

const ERRORS = {
  notOurFile: "هذا الملف لم يُشفَّر بواسطة «الخزنة» (ترويسة غير معروفة).",
  badVersion: (v) => `إصدار الملف (${v}) غير مدعوم من هذه النسخة.`,
  badKdf: "خوارزمية اشتقاق المفتاح في الملف غير مدعومة.",
  badIterations: "عدد تكرارات اشتقاق المفتاح في الملف غير منطقي.",
  tooSmall: "الملف صغير جداً ولا يحتوي على ترويسة صالحة.",
  truncated: "الملف مقطوع أو ناقص (لا توجد بيانات مشفّرة كاملة).",
  wrongKey: "كلمة المرور أو ملف المفتاح غير صحيح.",
  tampered: "فشل التحقق من سلامة البيانات: الملف تالف أو تم تعديله.",
  emptyData: "لا يمكن تشفير ملف فارغ.",
  passwordRequired: "كلمة المرور مطلوبة.",
  passwordTooLong: "كلمة المرور طويلة جداً.",
  oneSecret: "يجب تحديد كلمة مرور أو ملف مفتاح (واحدة فقط).",
  passwordForPasswordFile: "هذا الملف مُشفَّر بكلمة مرور، وليس بملف مفتاح.",
  keyForPasswordFile: "هذا الملف مُشفَّر بملف مفتاح، وليس بكلمة مرور.",
  keyLength: (n) => `طول المفتاح يجب أن يكون ${KEY_SIZE} بايت (256 بت)، وطول المفتاح المُعطى ${n} بايت.`,
  badKeyType: "نوع المفتاح غير مدعوم — مرّر بايتات أو نصاً.",
  badKeyFile: "ملف المفتاح غير صالح (تنسيق غير مفهوم أو ملف فارغ).",
  noWebCrypto: "متصفحك لا يدعم Web Crypto. افتح الموقع عبر HTTPS (أو localhost) في متصفح حديث.",
  badBase64: "النص المُدخل ليس Base64 صالحاً.",
  badData: "نوع بيانات غير مدعوم (المتوقع: بايتات أو نص).",
};

const PASSWORD_MIN_HINT =
  "لا اقتراحات — كلمة مرور ممتازة."; // يُستبدل في passwords.js

const requireCrypto = () => {
  if (typeof crypto === "undefined" || !crypto.subtle) {
    throw new SafeBoxError(ERRORS.noWebCrypto);
  }
};

/** يوحّد المدخلات إلى Uint8Array ويرفض الأنواع غير المدعومة. */
const toBytes = (data) => {
  if (data instanceof Uint8Array) return data;
  if (data instanceof ArrayBuffer) return new Uint8Array(data);
  if (ArrayBuffer.isView(data)) return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
  if (typeof data === "string") return enc.encode(data);
  if (Array.isArray(data)) return new Uint8Array(data);
  throw new SafeBoxError(ERRORS.badData);
};

/** يقرأ UInt32 big-endian مع مراعاة byteOffset (للتعامل مع الـ views). */
const readU32 = (bytes, offset) =>
  new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint32(offset, false);

const writeU32 = (bytes, offset, value) =>
  new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).setUint32(offset, value, false);

const bytesToHex = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");

/** مقارنة ثابتة الزمن (تمنع تسريب المعلومات عبر التوقيت). */
const constantTimeEqual = (a, b) => {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) diff |= a[i] ^ b[i];
  return diff === 0;
};

/* ------------------------------------------------ توليد القيم العشوائية --- */
const randomBytes = (length) => crypto.getRandomValues(new Uint8Array(length));

const generateSalt = () => randomBytes(SALT_SIZE);
const generateNonce = () => randomBytes(NONCE_SIZE);

const generateKeyBytes = (length = 32) => {
  const size = Math.max(16, Math.min(64, Number(length) || 32));
  return randomBytes(size);
};

const prettyPreset = (name) =>
  ({ fast: "سريع", balanced: "متوازن", paranoid: "فائق" }[name] || name);

const normalizeIterations = (iterations, preset) => {
  if (preset) {
    const value = ITERATION_PRESETS[preset];
    if (!value) throw new SafeBoxError(`إعداد جهد غير معروف: ${prettyPreset(preset)}`);
    return value;
  }
  if (iterations == null) return DEFAULT_ITERATIONS;
  const value = Number(iterations);
  if (!Number.isInteger(value) || value < MIN_ITERATIONS || value > MAX_ITERATIONS) {
    throw new SafeBoxError(
      `عدد التكرارات يجب أن يكون بين ${MIN_ITERATIONS.toLocaleString("en-US")} و ${MAX_ITERATIONS.toLocaleString("en-US")}.`
    );
  }
  return value;
};

/* ------------------------------------------------ الترويسة ---------------- */
const buildHeader = (kdfId, iterations, check, salt) => {
  const header = new Uint8Array(HEADER_SIZE);
  header.set(MAGIC, 0);
  header[4] = VERSION;
  header[5] = kdfId;
  writeU32(header, 6, iterations);
  header.set(check, 10);
  header.set(salt, 14);
  return header;
};

const parseHeader = (blob) => {
  if (blob.length < HEADER_SIZE) throw new InvalidFileError(ERRORS.tooSmall);
  for (let i = 0; i < MAGIC.length; i += 1) {
    if (blob[i] !== MAGIC[i]) throw new InvalidFileError(ERRORS.notOurFile);
  }
  const version = blob[4];
  if (version !== VERSION) throw new InvalidFileError(ERRORS.badVersion(version));
  const kdfId = blob[5];
  if (kdfId !== KDF_PBKDF2 && kdfId !== KDF_RAW_KEY) throw new InvalidFileError(ERRORS.badKdf);
  const iterations = readU32(blob, 6);
  if (kdfId === KDF_PBKDF2 && (iterations < MIN_ITERATIONS || iterations > MAX_ITERATIONS)) {
    throw new InvalidFileError(ERRORS.badIterations);
  }
  return {
    kdfId,
    iterations,
    check: blob.slice(10, 14),
    salt: blob.slice(14, 30),
    headerSize: HEADER_SIZE,
  };
};

/* ------------------------------------------------ المفاتيح ----------------- */
const sha256 = async (data) => new Uint8Array(await crypto.subtle.digest("SHA-256", toBytes(data)));

const keyCheckOf = async (rawKey) => (await sha256(rawKey)).slice(0, CHECK_SIZE);

const deriveAesKey = async (password, salt, iterations) => {
  const base = await crypto.subtle.importKey(
    "raw", enc.encode(password), "PBKDF2", false, ["deriveKey", "deriveBits"]
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: toBytes(salt), iterations, hash: "SHA-256" },
    base,
    { name: "AES-GCM", length: KEY_SIZE * 8 },
    true, // لازم للاستخراج: نحتاج البايتات لحساب بصمة التحقق فقط (تبقى في الذاكرة)
    ["encrypt", "decrypt"]
  );
};

const importRawKey = (rawKey) =>
  crypto.subtle.importKey("raw", toBytes(rawKey), "AES-GCM", true, ["encrypt", "decrypt"]);

const exportKeyBytes = async (aesKey) =>
  new Uint8Array(await crypto.subtle.exportKey("raw", aesKey));

/* ------------------------------------------------ ملفات المفاتيح ---------- */
const bytesToBase64 = (bytes) => {
  let binary = "";
  const chunk = 0x8000;
  const u8 = toBytes(bytes);
  for (let i = 0; i < u8.length; i += chunk) {
    binary += String.fromCharCode(...u8.subarray(i, i + chunk));
  }
  return btoa(binary);
};

const base64ToBytes = (input) => {
  const clean = String(input)
    .trim()
    .replace(/\s+/g, "")
    .replace(/-/g, "+")
    .replace(/_/g, "/");
  if (!clean || !/^[A-Za-z0-9+/]+={0,2}$/.test(clean)) {
    throw new SafeBoxError(ERRORS.badBase64);
  }
  const padded = clean + "=".repeat((4 - (clean.length % 4)) % 4);
  let binary;
  try {
    binary = atob(padded);
  } catch (err) {
    throw new SafeBoxError(ERRORS.badBase64);
  }
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes;
};

const hexToBytes = (text) => {
  if (text.length % 2 !== 0 || /[^0-9a-fA-F]/.test(text)) {
    throw new SafeBoxError(ERRORS.badKeyFile);
  }
  const bytes = new Uint8Array(text.length / 2);
  for (let i = 0; i < bytes.length; i += 1) bytes[i] = parseInt(text.slice(i * 2, i * 2 + 2), 16);
  return bytes;
};

/**
 * يستخرج المفتاح من ملف .key:
 *  - 32 بايت خام (مثل openssl rand 32)
 *  - Base64 أو hex مع تعليقات (#) وأسطر فارغة
 */
const parseKeyBlob = (raw) => {
  if (raw instanceof Uint8Array || raw instanceof ArrayBuffer || ArrayBuffer.isView(raw)) {
    const bytes = toBytes(raw);
    if (bytes.length === KEY_SIZE) return bytes;
    raw = String.fromCharCode(...bytes.subarray(0, 8192));
  } else if (typeof raw !== "string") {
    throw new SafeBoxError(ERRORS.badKeyType);
  }
  const tokens = [];
  for (const line of String(raw).split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    tokens.push(...trimmed.split(/\s+/));
  }
  const candidates = [];
  for (const token of tokens) {
    let bytes;
    try {
      bytes = token.length === 64 ? hexToBytes(token) : base64ToBytes(token);
    } catch (err) {
      continue;
    }
    if (bytes.length === KEY_SIZE) return bytes;
    candidates.push(bytes);
  }
  if (candidates.length) return candidates[0];
  throw new SafeBoxError(ERRORS.badKeyFile);
};

const coerceKey = (key) => {
  if (key instanceof Uint8Array) {
    if (key.length === KEY_SIZE) return key;
    throw new SafeBoxError(ERRORS.keyLength(key.length));
  }
  if (key instanceof ArrayBuffer) return coerceKey(new Uint8Array(key));
  if (typeof key !== "string") throw new SafeBoxError(ERRORS.badKeyType);
  const parsed = parseKeyBlob(key);
  if (parsed.length !== KEY_SIZE) throw new SafeBoxError(ERRORS.keyLength(parsed.length));
  return parsed;
};

/* ------------------------------------------------ التشفير ------------------ */
const encryptBytes = async (data, options = {}) => {
  requireCrypto();
  const { password, key, iterations, preset, filename, hideName } = options;
  data = toBytes(data);

  if (!data.length) throw new SafeBoxError(ERRORS.emptyData);
  if ((password == null) === (key == null)) throw new SafeBoxError(ERRORS.oneSecret);

  let keyBytes = null;
  let aesKey;
  let kdfId;
  let iterationsToUse;
  let salt;

  if (key != null) {
    keyBytes = coerceKey(key);
    aesKey = await importRawKey(keyBytes);
    kdfId = KDF_RAW_KEY;
    iterationsToUse = 0;
    salt = generateSalt(); // شكلي فقط، للحفاظ على ترويسة موحدة الطول
  } else {
    if (typeof password !== "string" || !password.trim()) {
      throw new SafeBoxError(ERRORS.passwordRequired);
    }
    if (password.length > MAX_PASSWORD_LENGTH) {
      throw new SafeBoxError(ERRORS.passwordTooLong);
    }
    iterationsToUse = normalizeIterations(iterations, preset);
    salt = generateSalt();
    aesKey = await deriveAesKey(password, salt, iterationsToUse);
    keyBytes = await exportKeyBytes(aesKey);
    kdfId = KDF_PBKDF2;
  }

  const check = await keyCheckOf(keyBytes);
  const header = buildHeader(kdfId, iterationsToUse, check, salt);
  const nonce = generateNonce();

  const meta = {
    name: hideName ? "encrypted" : (filename || "file.bin"),
    size: data.length,
    encrypted_at: new Date().toISOString(),
    tool: "SafeBox/1",
  };
  const metaJson = enc.encode(JSON.stringify(meta));
  const payload = new Uint8Array(4 + metaJson.length + data.length);
  writeU32(payload, 0, metaJson.length);
  payload.set(metaJson, 4);
  payload.set(data, 4 + metaJson.length);

  const cipher = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: nonce, additionalData: header, tagLength: TAG_BYTES * 8 },
      aesKey,
      payload
    )
  );

  const out = new Uint8Array(HEADER_SIZE + NONCE_SIZE + cipher.length);
  out.set(header, 0);
  out.set(nonce, HEADER_SIZE);
  out.set(cipher, HEADER_SIZE + NONCE_SIZE);
  return out;
};

/* ------------------------------------------------ فك التشفير --------------- */
const decryptBytes = async (blob, options = {}) => {
  requireCrypto();
  const { password, key } = options;
  if ((password == null) === (key == null)) throw new SafeBoxError(ERRORS.oneSecret);
  if (password != null && (typeof password !== "string" || !password.trim())) {
    throw new SafeBoxError(ERRORS.passwordRequired);
  }

  blob = toBytes(blob);
  const info = parseHeader(blob);
  if (blob.length < info.headerSize + NONCE_SIZE + TAG_BYTES) {
    throw new CorruptedFileError(ERRORS.truncated);
  }
  const nonce = blob.slice(info.headerSize, info.headerSize + NONCE_SIZE);
  const cipher = blob.slice(info.headerSize + NONCE_SIZE);
  const header = blob.slice(0, info.headerSize);

  let aesKey;
  let keyBytes;
  if (key != null) {
    keyBytes = coerceKey(key);
    if (info.kdfId === KDF_PBKDF2) throw new WrongKeyError(ERRORS.passwordForPasswordFile);
    aesKey = await importRawKey(keyBytes);
  } else {
    if (info.kdfId === KDF_RAW_KEY) throw new WrongKeyError(ERRORS.keyForPasswordFile);
    aesKey = await deriveAesKey(password, info.salt, info.iterations);
    keyBytes = await exportKeyBytes(aesKey);
  }

  const actualCheck = await keyCheckOf(keyBytes);
  if (!constantTimeEqual(actualCheck, info.check)) throw new WrongKeyError(ERRORS.wrongKey);

  let payload;
  try {
    payload = new Uint8Array(
      await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: nonce, additionalData: header, tagLength: TAG_BYTES * 8 },
        aesKey,
        cipher
      )
    );
  } catch (err) {
    throw new CorruptedFileError(ERRORS.tampered);
  }

  if (payload.length < 4) throw new CorruptedFileError(ERRORS.tampered);
  const metaLength = readU32(payload, 0);
  if (4 + metaLength > payload.length || metaLength > MAX_TEXT_BYTES) {
    throw new CorruptedFileError(ERRORS.tampered);
  }

  let meta;
  try {
    meta = JSON.parse(dec.decode(payload.slice(4, 4 + metaLength)));
  } catch (err) {
    throw new CorruptedFileError(ERRORS.tampered);
  }

  return {
    data: payload.slice(4 + metaLength),
    name: String(meta.name || "decrypted.bin"),
    meta,
  };
};

/* ------------------------------------------------ النصوص ------------------ */
const encryptText = async (text, options = {}) =>
  bytesToBase64(await encryptBytes(enc.encode(text), { ...options, filename: "text.txt" }));

const decryptText = async (token, options = {}) => {
  const blob = base64ToBytes(String(token).trim());
  const result = await decryptBytes(blob, options);
  return dec.decode(result.data);
};

/* ------------------------------------------------ الفحص ------------------- */
const inspectBlob = (blob) => {
  const info = parseHeader(toBytes(blob));
  return {
    algorithm: "AES-256-GCM",
    kdf: info.kdfId === KDF_PBKDF2 ? "PBKDF2-HMAC-SHA256" : "مفتاح مباشر (ملف مفتاح)",
    iterations: info.iterations,
    key_check: bytesToHex(info.check),
    salt: bytesToHex(info.salt),
    encrypted_size: blob.length,
  };
};

/* ------------------------------------------------ أسماء الملفات ----------- */
const outputName = (filename, encrypted) => {
  let base = String(filename ?? "file").replace(/\\/g, "/").split("/").pop() || "file";
  base = base.trim();
  if (encrypted) {
    return base.toLowerCase().endsWith(".sbox") ? base : `${base}.sbox`;
  }
  if (!base.toLowerCase().endsWith(".sbox")) return `${base}.decrypted`;
  return base.slice(0, -5) || "decrypted";
};

/* ------------------------------------------------ التصدير ------------------ */
if (typeof module !== "undefined" && module.exports) {
  // Node.js / CommonJS — يُستورد بـ: const sb = require("./crypto.js")
  module.exports = {
    MAGIC, VERSION, KDF_PBKDF2, KDF_RAW_KEY, SALT_SIZE, NONCE_SIZE, KEY_SIZE, CHECK_SIZE,
    HEADER_SIZE, TAG_BYTES, DEFAULT_ITERATIONS, ITERATION_PRESETS, MAX_FILE_SIZE,
    MAX_TEXT_BYTES, MAX_PASSWORD_LENGTH,
    SafeBoxError, InvalidFileError, WrongKeyError, CorruptedFileError,
    generateSalt, generateNonce, generateKeyBytes, deriveAesKey, importRawKey,
    parseKeyBlob, coerceKey, normalizeIterations, buildHeader, parseHeader,
    encryptBytes, decryptBytes, encryptText, decryptText, inspectBlob, outputName,
    bytesToBase64, base64ToBytes, bytesToHex, readU32, writeU32, toBytes,
    constantTimeEqual, sha256, keyCheckOf, requireCrypto,
  };
}
if (typeof window !== "undefined") {
  // المتصفح — نفس الملف يعمل داخل الويب بدون أي تعديل
  window.SafeBoxCrypto = {
    MAGIC_TEXT: "SBOX", VERSION, HEADER_SIZE, KEY_SIZE,
    ITERATION_PRESETS, DEFAULT_ITERATIONS, MAX_FILE_SIZE, MAX_TEXT_BYTES, MAX_PASSWORD_LENGTH,
    SafeBoxError, InvalidFileError, WrongKeyError, CorruptedFileError,
    encryptBytes, decryptBytes, encryptText, decryptText,
    inspectBlob, outputName, parseKeyBlob, coerceKey, generateKeyBytes,
    bytesToBase64, base64ToBytes, requireCrypto,
  };
}
