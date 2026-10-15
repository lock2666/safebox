"use strict";
/**
 * test_node.js — اختبارات نسخة Node.js من «الخزنة»
 *   node test_node.js
 */
const assert = require("assert");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { execFileSync } = require("child_process");

const crypto = require("./crypto.js");

const PW = "Xk9#mQ2vLp7$Wz4!Rt8^Bn6&";
const TMP = fs.mkdtempSync(path.join(os.tmpdir(), "safebox-node-"));

let passed = 0;
const failures = [];
async function test(name, fn) {
  try {
    await fn();
    passed += 1;
    console.log(`  ✅ ${name}`);
  } catch (err) {
    failures.push({ name, err });
    console.log(`  ❌ ${name} → ${err.message}`);
  }
}

(async () => {
  console.log("\n== محرك التشفير (crypto.js) ==");

  const content = "بيانات اختبار لنسخة Node.js " + "n".repeat(300);
  const data = new TextEncoder().encode(content);
  let blob;

  await test("تشفير وفك تشفير بكلمة مرور", async () => {
    blob = await crypto.encryptBytes(data, { password: PW, preset: "balanced", filename: "ملف.txt" });
    const back = await crypto.decryptBytes(blob, { password: PW });
    assert.strictEqual(new TextDecoder().decode(back.data), content);
    assert.strictEqual(back.name, "ملف.txt");
  });

  await test("ترويسة SBOX والإصدار", () => {
    assert.strictEqual(new TextDecoder().decode(blob.slice(0, 4)), "SBOX");
    assert.strictEqual(blob[4], 1);
    assert.strictEqual(blob.length - data.length >= 30, true);
  });

  await test("كلمة مرور خاطئة تُرفض", async () => {
    await assert.rejects(() => crypto.decryptBytes(blob, { password: "wrong" }),
      (e) => e instanceof crypto.WrongKeyError && e.message.includes("غير صحيح"));
  });

  await test("كلمة مرور فارغة تُرفض", async () => {
    await assert.rejects(() => crypto.decryptBytes(blob, { password: "   " }),
      (e) => e.message.includes("مطلوبة"));
  });

  await test("تعديل بايت واحد يُكتشف", async () => {
    const t = Uint8Array.from(blob);
    t[t.length - 25] ^= 0xff;
    await assert.rejects(() => crypto.decryptBytes(t, { password: PW }),
      (e) => e instanceof crypto.CorruptedFileError);
  });

  await test("تعديل الترويسة يُكتشف", async () => {
    const t = Uint8Array.from(blob);
    t[6] ^= 1;
    await assert.rejects(() => crypto.decryptBytes(t, { password: PW }));
  });

  await test("ملف ليس بصيغتنا يُرفض", async () => {
    await assert.rejects(
      () => crypto.decryptBytes(new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]), { password: PW }),
      (e) => e instanceof crypto.InvalidFileError);
  });

  await test("ملف مقطوع يُرفض", async () => {
    await assert.rejects(() => crypto.decryptBytes(blob.slice(0, 40), { password: PW }));
  });

  const key = crypto.generateKeyBytes(32);

  await test("توليد مفتاح 32 بايت", () => {
    assert.strictEqual(key.length, 32);
    assert.strictEqual(crypto.generateKeyBytes(32).length, 32);
  });

  await test("رفع/خفض طول المفتاح للحدود", () => {
    assert.strictEqual(crypto.generateKeyBytes(4).length, 16);
    assert.strictEqual(crypto.generateKeyBytes(1000).length, 64);
  });

  await test("دورة كاملة بملف مفتاح (بايتات خام)", async () => {
    const b = await crypto.encryptBytes(data, { key, filename: "k.txt" });
    const r = await crypto.decryptBytes(b, { key });
    assert.strictEqual(new TextDecoder().decode(r.data), content);
  });

  await test("ملف مفتاح نصي مع تعليقات", async () => {
    const text = "# مفتاح\n# تعليق\n" + crypto.bytesToBase64(key) + "\n";
    const b = await crypto.encryptBytes(data, { key: text, filename: "n.txt" });
    const r = await crypto.decryptBytes(b, { key: text });
    assert.strictEqual(new TextDecoder().decode(r.data), content);
  });

  await test("مفتاح بطول خاطئ يُرفض", async () => {
    await assert.rejects(() => crypto.encryptBytes(data, { key: new Uint8Array(16) }),
      (e) => e.message.includes("32 بايت"));
  });

  await test("بدون كلمة مرور ولا مفتاح يُرفض", async () => {
    await assert.rejects(() => crypto.encryptBytes(data, {}), (e) => e.message.includes("واحدة"));
    await assert.rejects(() => crypto.encryptBytes(data, { password: PW, key }));
  });

  await test("بيانات فارغة تُرفض", async () => {
    await assert.rejects(() => crypto.encryptBytes(new Uint8Array(0), { password: PW }));
  });

  await test("عدد تكرارات غير منطقي يُرفض", async () => {
    await assert.rejects(() => crypto.encryptBytes(data, { password: PW, iterations: 5 }));
  });

  await test("كل إعدادات الجهد تعمل", async () => {
    for (const preset of Object.keys(crypto.ITERATION_PRESETS)) {
      const b = await crypto.encryptBytes(data, { password: PW, preset, filename: "p.txt" });
      const r = await crypto.decryptBytes(b, { password: PW });
      assert.strictEqual(new TextDecoder().decode(r.data), content);
    }
  });

  await test("نص: تشفير وفك", async () => {
    const t = await crypto.encryptText("رسالة سرية", { password: PW });
    assert.strictEqual(await crypto.decryptText(t, { password: PW }), "رسالة سرية");
  });

  await test("نص: كلمة خاطئة تُرفض", async () => {
    const t = await crypto.encryptText("سر", { password: PW });
    await assert.rejects(() => crypto.decryptText(t, { password: "خطأ" }));
  });

  await test("نص: Base64 غير صالح يُرفض", async () => {
    await assert.rejects(() => crypto.decryptText("##", { password: PW }),
      (e) => e.message.includes("Base64"));
  });

  await test("فحص الترويسة بدون مفتاح", () => {
    const i = crypto.inspectBlob(blob);
    assert.strictEqual(i.algorithm, "AES-256-GCM");
    assert.strictEqual(i.iterations, 600000);
    assert.strictEqual(i.kdf, "PBKDF2-HMAC-SHA256");
    assert.match(i.key_check, /^[0-9a-f]{8}$/);
  });

  await test("إخفاء اسم الملف الأصلي", async () => {
    const b = await crypto.encryptBytes(data, { password: PW, filename: "سر.pdf", hideName: true });
    const r = await crypto.decryptBytes(b, { password: PW });
    assert.strictEqual(r.name, "encrypted");
  });

  await test("أسماء المخرجات", () => {
    assert.strictEqual(crypto.outputName("a.pdf", true), "a.pdf.sbox");
    assert.strictEqual(crypto.outputName("a.pdf.sbox", false), "a.pdf");
    assert.strictEqual(crypto.outputName("x.txt", false), "x.txt.decrypted");
  });

  await test("Base64 في الاتجاهين", async () => {
    const bytes = new Uint8Array([0, 1, 250, 255, 128]);
    assert.deepStrictEqual(Array.from(crypto.base64ToBytes(crypto.bytesToBase64(bytes))),
      Array.from(bytes));
  });

  console.log("\n== سطر الأوامر (node.js) ==");
  const run = (args, opts = {}) =>
    execFileSync(process.execPath, [path.join(__dirname, "node.js"), ...args],
      { encoding: "utf8", ...opts });

  const sample = path.join(TMP, "sample.txt");
  fs.writeFileSync(sample, "محتوى سري للاختبار " + "s".repeat(500));

  await test("--help يعرض المساعدة", () => {
    const out = run(["--help"]);
    assert.ok(out.includes("الاستخدام"));
    assert.ok(out.includes("encrypt"));
  });

  await test("encrypt ينشئ ملف .sbox", () => {
    const out = run(["encrypt", sample, "-p", PW, "-o", path.join(TMP, "a.sbox"), "--force"]);
    assert.ok(fs.existsSync(path.join(TMP, "a.sbox")));
    assert.ok(out.includes("تم التشفير"));
  });

  await test("decrypt يستعيد الملف الأصلي", () => {
    run(["decrypt", path.join(TMP, "a.sbox"), "-p", PW, "-o", path.join(TMP, "back.txt"), "--force"]);
    assert.strictEqual(fs.readFileSync(path.join(TMP, "back.txt"), "utf8"),
      fs.readFileSync(sample, "utf8"));
  });

  await test("decrypt بكلمة خاطئة يفشل برسالة واضحة", () => {
    let err = null;
    try {
      run(["decrypt", path.join(TMP, "a.sbox"), "-p", "wrong", "-o", path.join(TMP, "bad.txt"), "--force"]);
    } catch (e) {
      err = e;
    }
    assert.ok(err, "كان يجب أن يفشل");
    assert.ok(String(err.stderr || err.message).includes("غير صحيح"));
  });

  await test("keygen ثم التشفير/الفك بملف مفتاح", () => {
    const keyPath = path.join(TMP, "my.key");
    run(["keygen", "-o", keyPath, "--length", "32", "--force"]);
    assert.ok(fs.existsSync(keyPath));
    run(["encrypt", sample, "-k", keyPath, "-o", path.join(TMP, "k.sbox"), "--force"]);
    run(["decrypt", path.join(TMP, "k.sbox"), "-k", keyPath, "-o", path.join(TMP, "k.txt"), "--force"]);
    assert.strictEqual(fs.readFileSync(path.join(TMP, "k.txt"), "utf8"), fs.readFileSync(sample, "utf8"));
  });

  await test("info يعرض تفاصيل الملف", () => {
    const out = run(["info", path.join(TMP, "a.sbox")]);
    assert.ok(out.includes("AES-256-GCM"));
    assert.ok(out.includes("600,000"));
  });

  await test("info لملف غير مشفّر يعطي خطأ واضح", () => {
    let err = null;
    try {
      run(["info", sample]);
    } catch (e) {
      err = e;
    }
    assert.ok(err);
    assert.ok(String(err.stderr || err.message).includes("لم يُشفَّر"));
  });

  await test("text -t يشفر النص كنص Base64", () => {
    const out = run(["text", "-t", "رسالة عبر سطر الأوامر", "-p", PW]);
    const token = out.split("\n").filter((l) => l.trim() && !l.includes("النسخ")).pop();
    assert.match(token.trim(), /^[A-Za-z0-9+/=]+$/);
    const back = run(["text", "-t", token.trim(), "-p", PW]);
    assert.ok(back.includes("رسالة عبر سطر الأوامر"));
  });

  await test("ملف غير موجود يعطي خطأ واضح", () => {
    let err = null;
    try {
      run(["encrypt", path.join(TMP, "nope.txt"), "-p", PW]);
    } catch (e) {
      err = e;
    }
    assert.ok(err);
    assert.ok(String(err.stderr || err.message).includes("غير موجود"));
  });

  await test("بدون وسائط يعرض المساعدة", () => {
    let err = null;
    try {
      run([]);
    } catch (e) {
      err = e;
    }
    assert.ok(err);
  });

  await test("أمر غير معروف يُرفض", () => {
    let err = null;
    try {
      run(["fly"]);
    } catch (e) {
      err = e;
    }
    assert.ok(err);
    assert.ok(String(err.stderr || err.message).includes("غير معروف"));
  });

  fs.rmSync(TMP, { recursive: true, force: true });

  console.log(`\n${"=".repeat(56)}`);
  console.log(`نجح ${passed} / فشل ${failures.length}`);
  console.log("=".repeat(56));
  process.exit(failures.length ? 1 : 0);
})().catch((err) => {
  console.error("خطأ غير متوقع:", err);
  process.exit(1);
});
