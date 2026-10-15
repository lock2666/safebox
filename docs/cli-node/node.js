#!/usr/bin/env node
/**
 * node.js — نسخة Node.js من «الخزنة» (لا تحتاج أي حزمة خارجية)
 *
 *   node node.js encrypt report.pdf -p pass -o secret.sbox
 *   node node.js keygen -o key.key
 *   node node.js decrypt secret.sbox -p pass -o report.pdf
 *   node node.js info secret.sbox
 */
"use strict";

const fs = require("fs");
const path = require("path");
const readline = require("readline");

const crypto = require("./crypto.js");

/* ---------------------------------------------------------------- الألوان */
const useColor = process.stdout.isTTY && !process.env.NO_COLOR;
const paint = (code, text) => (useColor ? `\x1b[${code}m${text}\x1b[0m` : text);
const info = (msg) => console.log(paint("36", msg));          // سماوي
const good = (msg) => console.log(paint("32", `✅ ${msg}`));   // أخضر
const warn = (msg) => console.warn(paint("33", `⚠️  ${msg}`)); // أصفر
const fail = (msg) => console.error(paint("31", `✋ ${msg}`)); // أحمر

/* ---------------------------------------------------------------- وسائط */
function parseArgs(argv) {
  const out = { _: [] };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--help" || arg === "-h") out.help = true;
    else if (arg === "--version" || arg === "-V") out.version = true;
    else if (arg === "--verbose" || arg === "-v") out.verbose = true;
    else if (arg === "--password" || arg === "-p") out.password = argv[++i];
    else if (arg === "--key" || arg === "-k") out.key = argv[++i];
    else if (arg === "--output" || arg === "-o") out.output = argv[++i];
    else if (arg === "--preset") out.preset = argv[++i];
    else if (arg === "--length") out.length = Number(argv[++i]);
    else if (arg === "--text" || arg === "-t") out.text = argv[++i];
    else if (arg === "--force" || arg === "-f") out.force = true;
    else if (arg.startsWith("--")) fail(`خيار غير معروف: ${arg}`);
    else out._.push(arg);
  }
  return out;
}

function usage() {
  console.log(`
الخزنة — تشفير وفك تشفير الملفات (Node.js)

الاستخدام:
  node node.js <أمر> [خيارات]

الأوامر:
  encrypt <ملف>      تشفير ملف (ينتج <ملف>.sbox)
  decrypt <ملف>      فك تشفير ملف (يستعيد الاسم الأصلي)
  info <ملف>         عرض ترويسة ملف مشفّر بدون كلمة مرور
  keygen             توليد ملف مفتاح (.key)
  text               تشفير أو فك نص (-t "نص") — الناتج/المدخل Base64

الخيارات:
  -p, --password <ك>  كلمة المرور (أو يُطلب تفاعلياً بأمان)
  -k, --key <ملف>     ملف المفتاح بدلاً من كلمة المرور
  -o, --output <مسار> مسار الملف الناتج
  --preset <اسم>      fast | balanced | paranoid (الافتراضي: balanced)
  --length <بايت>     طول المفتاح عند keygen (32 افتراضياً)
  -t, --text <نص>     النص المراد تشفيره/فكّه
  -f, --force         استبدال الملف الناتج بدون سؤال
  -h, --help          عرض هذه المساعدة
  -v, --verbose       تفاصيل أكثر

أمثلة:
  node node.js encrypt report.pdf -p "كلمة-قوية-2026"
  node node.js encrypt photo.jpg -k my.key --preset paranoid
  node node.js decrypt report.pdf.sbox -p "كلمة-قوية-2026"
  node node.js keygen --length 48 -o my.key
  node node.js info report.pdf.sbox
  node node.js text -t "رسالة سرية" -p "كلمة-قوية-2026"
`);
}

/* ---------------------------------------------------------------- تفاعلي */
/** قراءة كلمة مرور من stdin دون ظهورها على الشاشة. */
async function promptPassword(message) {
  process.stdout.write(message);
  try {
    if (process.stdin.setRawMode && process.stdin.isTTY) {
      process.stdin.setRawMode(true);
    }
  } catch (err) { /* ليس TTY — نتابع بدون إخفاء */ }

  let value = "";
  await new Promise((resolve) => {
    const onData = (chunk) => {
      const str = chunk.toString("utf8");
      for (const ch of str) {
        if (ch === "\n" || ch === "\r" || ch === "\u0004") {
          process.stdin.removeListener("data", onData);
          resolve();
          return;
        }
        if (ch === "\u007f" || ch === "\b") {
          value = value.slice(0, -1);
          process.stdout.write("\b \b");
        } else if (ch >= " ") {
          value += ch;
          process.stdout.write("*");
        }
      }
    };
    process.stdin.on("data", onData);
    process.stdin.resume();
  });

  try {
    if (process.stdin.setRawMode && process.stdin.isTTY) {
      process.stdin.setRawMode(false);
    }
  } catch (err) { /* تجاهل */ }
  process.stdout.write("\n");
  return value;
}

/* ---------------------------------------------------------------- أدوات */
const readKey = (keyPath) => {
  const stat = fs.statSync(keyPath);  // يرمي إن الملف غير موجود
  if (!stat.isFile()) throw new Error(`ليس ملفاً: ${keyPath}`);
  const bytes = new Uint8Array(fs.readFileSync(keyPath));
  return crypto.parseKeyBlob(bytes);
};

const readKeyText = (keyPath) => {
  const bytes = new Uint8Array(fs.readFileSync(keyPath));
  return crypto.parseKeyBlob(bytes);
};

function ensureWritable(target, force) {
  if (!fs.existsSync(target)) return true;
  if (force) return true;
  return new Promise((resolve) => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    rl.question(`الملف موجود: ${target} — استبداله؟ (y/N) `, (answer) => {
      rl.close();
      resolve(/^y(es)?$/i.test(answer.trim()));
    });
  });
}

const formatBytes = (n) => {
  if (n < 1024) return `${n} بايت`;
  const units = ["ك.بايت", "م.بايت", "غ.بايت"];
  let v = n / 1024, i = 0;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i += 1; }
  return `${v.toFixed(v < 10 ? 2 : 1)} ${units[i]}`;
};

async function resolveSecret(args, message) {
  if (args.key && args.password) {
    fail("اختر طريقة واحدة فقط: كلمة مرور (-p) أو ملف مفتاح (-k).");
    process.exit(2);
  }
  if (args.key) {
    try {
      return { key: readKey(args.key), password: undefined };
    } catch (err) {
      fail(readKeyErrorMessage(err, args.key));
      process.exit(1);
    }
  }
  let password = args.password;
  if (!password) {
    password = await promptPassword(message);
    if (!password) {
      fail("كلمة المرور مطلوبة.");
      process.exit(2);
    }
  }
  return { password, key: undefined };
}

function readKeyErrorMessage(err, keyPath) {
  if (err && err.code === "ENOENT") return `ملف المفتاح غير موجود: ${keyPath}`;
  return `ملف المفتاح غير صالح: ${err.message}`;
}

/* ---------------------------------------------------------------- الأوامر */
async function cmdEncrypt(args) {
  if (!args._[1]) return fail("حدّد الملف المراد تشفيره. (--help للمساعدة)");
  const input = path.resolve(args._[1]);
  const preset = args.preset || "balanced";
  if (!crypto.ITERATION_PRESETS[preset]) {
    return fail(`إعداد جهد غير معروف: ${preset} (الخيارات: ${Object.keys(crypto.ITERATION_PRESETS).join(", ")})`);
  }

  let stat;
  try {
    stat = fs.statSync(input);
  } catch (err) {
    return fail(`الملف غير موجود: ${input}`);
  }
  if (!stat.isFile()) return fail(`المسار ليس ملفاً: ${input}`);
  if (stat.size > crypto.MAX_FILE_SIZE) {
    return fail(`حجم الملف ${formatBytes(stat.size)} يتجاوز الحد (${formatBytes(crypto.MAX_FILE_SIZE)}).`);
  }
  const data = new Uint8Array(fs.readFileSync(input));
  if (!data.length) return fail("لا يمكن تشفير ملف فارغ.");

  const { password, key } = await resolveSecret(args, "أدخل كلمة المرور للتشفير: ");
  info(`🔒 جارٍ التشفير (${preset})...`);

  let blob;
  try {
    blob = await crypto.encryptBytes(data, {
      password, key, preset, filename: path.basename(input),
    });
  } catch (err) {
    return fail(`فشل التشفير: ${err.message}`);
  }

  const output = args.output || crypto.outputName(input, true);

  const ok = await ensureWritable(output, args.force);
  if (!ok) return fail("أُلغي الأمر (لم يُستبدل الملف).");

  fs.writeFileSync(output, Buffer.from(blob));
  good(`تم التشفير: ${output}`);
  info(`   الأصلي: ${formatBytes(data.length)} → المشفّر: ${formatBytes(blob.length)} (زيادة ${formatBytes(blob.length - data.length)})`);
  info(`   الخوارزمية: AES-256-GCM | ${password ? `PBKDF2-HMAC-SHA256 (${crypto.ITERATION_PRESETS[preset].toLocaleString("en-US")} تكرار)` : "مفتاح مباشر"}`);
  warn("احتفظ بكلمة المرور/ملف المفتاح — بدونهما لا يمكن استعادة البيانات.");
  return true;
}

async function cmdDecrypt(args) {
  if (!args._[1]) return fail("حدّد الملف المشفّر. (--help للمساعدة)");
  const input = path.resolve(args._[1]);
  let blob;
  try {
    blob = new Uint8Array(fs.readFileSync(input));
  } catch (err) {
    return fail(readKeyErrorMessage(err, input).replace("ملف المفتاح", "الملف"));
  }

  info("🔓 جارٍ فك التشفير...");
  const { password, key } = await resolveSecret(args, "أدخل كلمة المرور لفك التشفير: ");
  let result;
  try {
    result = await crypto.decryptBytes(blob, { password, key });
  } catch (err) {
    if (err instanceof crypto.WrongKeyError) return fail(`تعذّر فك التشفير: ${err.message}`);
    if (err instanceof crypto.InvalidFileError) return fail(err.message);
    if (err instanceof crypto.CorruptedFileError) return fail(err.message);
    return fail(`خطأ: ${err.message}`);
  }

  const output = args.output || path.basename(result.name);
  const ok = await ensureWritable(output, args.force);
  if (!ok) return fail("أُلغي الأمر (لم يُستبدل الملف).");

  fs.writeFileSync(output, Buffer.from(result.data));
  good(`تم فك التشفير: ${output}`);
  info(`   الحجم: ${formatBytes(result.data.length)} | الاسم الأصلي: ${result.meta.name}`);
  return true;
}

function cmdInfo(args) {
  if (!args._[1]) return fail("حدّد الملف المشفّر. (--help للمساعدة)");
  const input = path.resolve(args._[1]);
  try {
    const blob = new Uint8Array(fs.readFileSync(input));
    const i = crypto.inspectBlob(blob);
    info(`🔎 ${input}`);
    console.log(`   الخوارزمية      : ${i.algorithm}`);
    console.log(`   اشتقاق المفتاح : ${i.kdf}`);
    console.log(`   عدد التكرارات  : ${i.iterations ? i.iterations.toLocaleString("en-US") : "—"}`);
    console.log(`   بصمة المفتاح   : ${i.key_check}`);
    console.log(`   الحجم المشفّر   : ${formatBytes(i.encrypted_size)}`);
    console.log(`   Salt (hex)      : ${i.salt}`);
    return true;
  } catch (err) {
    if (err instanceof crypto.InvalidFileError) return fail(err.message);
    return fail(readKeyErrorMessage(err, input).replace("ملف المفتاح", "الملف"));
  }
}

async function cmdKeygen(args) {
  const length = Math.max(16, Math.min(64, Number(args.length) || 32));
  const key = crypto.generateKeyBytes(length);
  const output = args.output || "safebox.key";

  const body =
    "# مفتاح «الخزنة» — لا تشاركه مع أحد واحتفظ بنسخة احتياطية منه.\n" +
    "# من يملك هذا الملف يستطيع فك تشفير ملفاتك.\n" +
    crypto.bytesToBase64(key) + "\n";

  const ok = await ensureWritable(output, args.force);
  if (!ok) return fail("أُلغي الأمر (لم يُستبدل الملف).");

  fs.writeFileSync(output, body);
  good(`تم توليد المفتاح (${length * 8} بت): ${output}`);
  const check = crypto.bytesToHex((await crypto.keyCheckOf(key)));
  info(`   بصمة المفتاح: ${check}`);
  warn("إن فقدت هذا الملف فلا يمكن فك تشفير ملفاتك أبداً.");
  return true;
}

async function cmdText(args) {
  const text = args.text || (await promptText());
  if (!text) return fail("النص مطلوب (استخدم -t أو أدخله).");
  const { password, key } = await resolveSecret(args, "كلمة المرور: ");

  const looksEncrypted = /^[A-Za-z0-9+/_-]+={0,2}$/.test(text) && text.length > 40;
  const mode = looksEncrypted ? "decrypt" : "encrypt";

  try {
    if (mode === "encrypt") {
      const token = await crypto.encryptText(text, { password, key });
      info("النص المشفّر (انسخه كاملاً):");
      console.log(token);
    } else {
      const plain = await crypto.decryptText(text, { password, key });
      info("النص الأصلي:");
      console.log(plain);
    }
    return true;
  } catch (err) {
    return fail(`فشل: ${err.message}`);
  }
}

/** إدخال نص من stdin (سطر واحد أو حتى EOF). */
async function promptText() {
  if (process.stdin.isTTY) return null;
  const chunks = [];
  for await (const chunk of process.stdin) chunks.push(chunk);
  return Buffer.concat(chunks).toString("utf8").trim();
}

/* ---------------------------------------------------------------- رئيسي */
async function main() {
  const args = parseArgs(process.argv.slice(2));
  const command = args._[0];

  if (args.version) {
    console.log(`الخزنة (Node.js) — صيغة SBOX الإصدار ${crypto.VERSION}`);
    return 0;
  }
  if (!command || args.help) {
    usage();
    // --help/-h: نجاح. بدون أمر وبدون طلب مساعدة: خطأ استخدام.
    return args.help || args.version ? 0 : 1;
  }

  switch (command) {
    case "encrypt":
    case "enc":
      return (await cmdEncrypt(args)) ? 0 : 1;
    case "decrypt":
    case "dec":
      return (await cmdDecrypt(args)) ? 0 : 1;
    case "info":
      return cmdInfo(args) ? 0 : 1;
    case "keygen":
    case "key":
      return (await cmdKeygen(args)) ? 0 : 1;
    case "text":
      return (await cmdText(args)) ? 0 : 1;
    default:
      fail(`أمر غير معروف: ${command}`);
      usage();
      return 1;
  }
}

main()
  .then((code) => process.exit(code))
  .catch((err) => {
    fail(err && err.message ? err.message : String(err));
    process.exit(1);
  });
