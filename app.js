/*!
 * app.js — منطق واجهة نسخة الويب (كل شيء داخل المتصفح، بدون شبكة).
 */
(() => {
  "use strict";

  const C = window.SafeBoxCrypto;
  const P = window.SafeBoxPasswords;
  const $ = (sel, root = document) => root.querySelector(sel);
  const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

  const errorBox = $("#error-box");
  const successBox = $("#success-box");
  const resultCard = $("#result-card");

  /* ------------------------------------------------------------ أدوات عرض */
  const showError = (message) => {
    successBox.hidden = true;
    errorBox.textContent = "⚠️ " + message;
    errorBox.hidden = false;
    errorBox.scrollIntoView({ behavior: "smooth", block: "center" });
  };
  const showSuccess = (message) => {
    errorBox.hidden = true;
    successBox.textContent = "✅ " + message;
    successBox.hidden = false;
  };
  const clearMessages = () => { errorBox.hidden = true; successBox.hidden = true; };

  const formatBytes = (bytes) => {
    if (!Number.isFinite(bytes)) return "—";
    if (bytes < 1024) return `${bytes} بايت`;
    const units = ["ك.بايت", "م.بايت", "غ.بايت"];
    let value = bytes / 1024, index = 0;
    while (value >= 1024 && index < units.length - 1) { value /= 1024; index += 1; }
    return `${value.toFixed(value < 10 ? 2 : 1)} ${units[index]}`;
  };

  const readAsBytes = (file) => file.arrayBuffer().then((buffer) => new Uint8Array(buffer));

  /** يقرأ ملف المفتاح: Base64/hex نصي أو 32 بايت خام. */
  async function readKeyFile(input) {
    const file = input.files && input.files[0];
    if (!file) throw new C.SafeBoxError("اختر ملف المفتاح.");
    if (file.size > 1024 * 1024) {
      throw new C.SafeBoxError("ملف المفتاح كبير جداً (يجب أن يكون بضعة بايتات).");
    }
    const bytes = await readAsBytes(file);
    if (!bytes.length) throw new C.SafeBoxError("ملف المفتاح فارغ.");
    return C.parseKeyBlob(bytes);
  }

  async function setBusy(button, busy, label, work) {
    if (!busy) return work();
    const original = button.innerHTML;
    button.innerHTML = `<span class="spinner"></span>${label}`;
    button.disabled = true;
    try {
      return await work();
    } finally {
      button.innerHTML = original;
      button.disabled = false;
    }
  }

  function downloadBytes(bytes, filename, mime = "application/octet-stream") {
    const blob = new Blob([bytes], { type: mime });
    const url = URL.createObjectURL(blob);
    const link = $("#result-download");
    link.href = url;
    link.download = filename;
    link.textContent = `⬇️ تحميل ${filename}`;
    link.click();
    return filename;
  }

  function renderResult(rows, title, warning = "") {
    $("#result-title").textContent = title;
    $("#result-meta").innerHTML = rows
      .map(([k, v, rtl]) => `<dt>${k}</dt><dd class="${rtl ? "rtl" : ""}">${v}</dd>`)
      .join("");
    const note = $("#result-warning");
    note.hidden = !warning;
    if (warning) note.textContent = "⚠️ " + warning;
    resultCard.hidden = false;
    resultCard.scrollIntoView({ behavior: "smooth", block: "center" });
  }

  /* --------------------------------------------------------------- التبويبات */
  const tabs = $$(".tab");
  tabs.forEach((tab) => {
    tab.addEventListener("click", () => {
      tabs.forEach((t) => {
        const active = t === tab;
        t.classList.toggle("active", active);
        t.setAttribute("aria-selected", active ? "true" : "false");
      });
      $$(".panel").forEach((panel) => { panel.hidden = panel.id !== `panel-${tab.dataset.tab}`; });
      clearMessages();
      resultCard.hidden = true;
    });
  });

  /* ---------------------------------------------------------- سحب وإفلات */
  function wireDropzone(zoneId, inputId, onChosen) {
    const zone = $(`#${zoneId}`);
    const input = $(`#${inputId}`);
    if (!zone || !input) return;
    zone.addEventListener("click", () => input.click());
    input.addEventListener("change", () => { if (input.files[0]) onChosen(input.files[0]); });
    ["dragenter", "dragover"].forEach((evt) =>
      zone.addEventListener(evt, (e) => { e.preventDefault(); zone.classList.add("dragover"); }));
    ["dragleave", "drop"].forEach((evt) =>
      zone.addEventListener(evt, (e) => { e.preventDefault(); zone.classList.remove("dragover"); }));
    zone.addEventListener("drop", (e) => {
      const file = e.dataTransfer.files && e.dataTransfer.files[0];
      if (!file) return;
      const dt = new DataTransfer();
      dt.items.add(file);
      input.files = dt.files;
      onChosen(file);
    });
  }

  /* ---------------------------------------------------- وضع كلمة المرور/المفتاح */
  const selectedMode = (form) => {
    if (!form) return "password";
    const checked = $("input[name=secret_mode]:checked", form);
    return checked ? checked.value : "password";
  };

  $$(".segmented").forEach((group) => {
    $$("input[type=radio]", group).forEach((radio) =>
      radio.addEventListener("change", () => {
        $$(".seg", group).forEach((seg) => seg.classList.toggle("active", $("input", seg).checked));
        const panel = group.closest(".panel");
        const suffix = panel && panel.dataset.suffix;
        if (!suffix) return; // مبدّل بلا حقول مرتبطة (مثل تبويب النص)
        const useKey = selectedMode(panel) === "key";
        const pwField = $("#field-password-" + suffix);
        const keyField = $("#field-key-" + suffix);
        if (pwField) pwField.hidden = useKey;
        if (keyField) keyField.hidden = !useKey;
      }));
  });

  $$("[data-toggle-pw]").forEach((btn) =>
    btn.addEventListener("click", () => {
      const input = $("#" + btn.dataset.togglePw);
      input.type = input.type === "password" ? "text" : "password";
      btn.textContent = input.type === "password" ? "👁️" : "🙈";
    }));

  /* ----------------------------------------------------- قوة كلمة المرور */
  const meter = $("#pw-meter-encrypt span");
  const meterLabel = $("#pw-label-encrypt");
  const tips = $("#pw-tips-encrypt");

  const paintMeter = ({ level, color, bits, suggestions }) => {
    if (meter) { meter.style.background = color; meter.style.width = "0%"; requestAnimationFrame(() => {
      meter.style.width = `${(bits >= 60 ? 100 : bits >= 48 ? 80 : bits >= 36 ? 60 : bits >= 28 ? 40 : 20)}%`;
    }); }
    if (meterLabel) {
      meterLabel.innerHTML = `القوة: <strong style="color:${color}">${level}</strong> <span style="opacity:.7">(${bits} بت)</span>`;
    }
    if (tips) tips.innerHTML = (suggestions || []).map((s) => `<li>${s}</li>`).join("");
  };

  const checkPassword = (password) => {
    if (!password) {
      if (meter) meter.style.width = "0";
      if (meterLabel) meterLabel.textContent = "القوة: —";
      if (tips) tips.textContent = "";
      return;
    }
    paintMeter(P.estimateStrength(password));
  };

  const encryptPw = $("#encrypt-password");
  if (encryptPw) encryptPw.addEventListener("input", (e) => checkPassword(e.target.value));

  $$("[data-suggest-pw]").forEach((btn) =>
    btn.addEventListener("click", () => {
      const input = $("#" + btn.dataset.suggestPw);
      input.value = P.generatePassword(20);
      input.type = "text";
      checkPassword(input.value);
      showSuccess("وُلِّدت كلمة مرور قوية — انسخها واحفظها في مكان آمن.");
      setTimeout(() => { successBox.hidden = true; }, 4000);
    }));

  /* --------------------------------------------------------------- تشفير ملف */
  const encryptForm = $("#form-encrypt");
  const encryptPanel = $("#panel-encrypt");
  if (encryptPanel) encryptPanel.dataset.suffix = "encrypt";
  const decryptPanel = $("#panel-decrypt");
  if (decryptPanel) decryptPanel.dataset.suffix = "decrypt";

  let encryptFile = null;

  wireDropzone("drop-encrypt", "encrypt-file", (file) => {
    if (file.size > C.MAX_FILE_SIZE) { showError("حجم الملف يتجاوز الحد المسموح (64 ميغابايت)."); return; }
    encryptFile = file;
    $("#encrypt-file-name").hidden = false;
    $("#encrypt-file-name").textContent = `📄 ${file.name} — ${formatBytes(file.size)}`;
    clearMessages();
  });

  if (encryptForm) {
    encryptForm.addEventListener("submit", async (event) => {
      event.preventDefault();
      clearMessages();
      try {
        if (!encryptFile) { showError("اختر ملفاً أولاً."); return; }
        const mode = selectedMode(encryptForm);
        let keyBytes = null;
        if (mode === "key") {
          keyBytes = await readKeyFile($("#encrypt-keyfile"));
        } else {
          const password = $("#encrypt-password").value;
          if (!password) { showError("أدخل كلمة المرور."); return; }
          const strength = P.estimateStrength(password);
          if (strength.weak) {
            const ok = confirm(
              `${strength.suggestions[0]}\n\nكلمة المرور (${strength.level} — ${strength.bits} بت) قد تُخترق بالتخمين.\nهل تريد المتابعة على أي حال؟`
            );
            if (!ok) return;
          }
        }
        const data = await readAsBytes(encryptFile);
        const preset = $("#encrypt-preset").value;
        const iterations = C.ITERATION_PRESETS[preset] || C.DEFAULT_ITERATIONS;
        const blob = await setBusy($("#btn-encrypt"), true, "جارٍ التشفير…", () =>
          C.encryptBytes(data, {
            password: mode === "key" ? undefined : $("#encrypt-password").value,
            key: mode === "key" ? keyBytes : undefined,
            preset,
            filename: encryptFile.name,
            hideName: $("#encrypt-hide-name").checked,
          }));

        const outName = C.outputName(encryptFile.name, true);
        downloadBytes(blob, outName);
        const strength = mode === "key" ? null : P.estimateStrength($("#encrypt-password").value);
        renderResult(
          [
            ["اسم الملف الأصلي", encryptFile.name, true],
            ["الحجم الأصلي", formatBytes(data.length), true],
            ["الحجم بعد التشفير", formatBytes(blob.length), true],
            ["حجم زائد (الترويسة + الوسم)", formatBytes(blob.length - data.length), true],
            ["الخوارزمية", "AES-256-GCM", false],
            mode === "key"
              ? ["اشتقاق المفتاح", "مفتاح مباشر (ملف مفتاح)", false]
              : ["اشتقاق المفتاح", "PBKDF2-HMAC-SHA256", false],
            mode === "key"
              ? ["طول المفتاح", `${keyBytes.length * 8} بت`, false]
              : ["عدد التكرارات", iterations.toLocaleString("en-US"), false],
            $("#encrypt-hide-name").checked ? ["الاسم الأصلي", "مخفي داخل الملف", true] : null,
          ].filter(Boolean),
          "✅ تم التشفير بنجاح",
          strength && strength.weak ? "كلمة المرور ضعيفة — يُفضّل استخدام كلمة أقوى." : ""
        );
        showSuccess(`جاهز للتنزيل: ${outName}`);
      } catch (err) {
        showError(err && err.message ? err.message : String(err));
      }
    });
  }

  /* --------------------------------------------------------------- فك التشفير */
  const decryptForm = $("#form-decrypt");
  let decryptFile = null;

  async function showBlobInfo(file) {
    const box = $("#decrypt-info");
    box.hidden = false;
    box.innerHTML = "⏳ جارٍ قراءة ترويسة الملف…";
    try {
      const info = C.inspectBlob(await readAsBytes(file));
      const rows = [
        ["الخوارزمية", info.algorithm],
        ["اشتقاق المفتاح", info.kdf],
        info.iterations ? ["عدد التكرارات", info.iterations.toLocaleString("en-US")] : null,
        ["بصمة المفتاح المطلوبة", info.key_check],
        ["الحجم المشفّر", formatBytes(info.encrypted_size)],
      ].filter(Boolean);
      box.innerHTML = `<h4>🔎 ترويسة الملف</h4><dl class="meta">${rows
        .map(([k, v]) => `<dt>${k}</dt><dd>${v}</dd>`).join("")}</dl>`;
    } catch (err) {
      box.innerHTML = `<span style="color:var(--danger)">⚠️ ${err.message}</span>`;
    }
  }

  wireDropzone("drop-decrypt", "decrypt-file", (file) => {
    decryptFile = file;
    $("#decrypt-file-name").hidden = false;
    $("#decrypt-file-name").textContent = `🔐 ${file.name} — ${formatBytes(file.size)}`;
    clearMessages();
    showBlobInfo(file);
  });

  if (decryptForm) {
    decryptForm.addEventListener("submit", async (event) => {
      event.preventDefault();
      clearMessages();
      try {
        if (!decryptFile) { showError("اختر الملف المشفّر أولاً."); return; }
        const mode = selectedMode(decryptForm);
        let keyBytes = null;
        if (mode === "key") {
          keyBytes = await readKeyFile($("#decrypt-keyfile"));
        }
        const blob = await readAsBytes(decryptFile);
        const started = Date.now();
        const result = await setBusy($("#btn-decrypt"), true, "جارٍ فك التشفير…", () =>
          C.decryptBytes(blob, {
            password: mode === "key" ? undefined : $("#decrypt-password").value,
            key: mode === "key" ? keyBytes : undefined,
          }));
        const elapsed = ((Date.now() - started) / 1000).toFixed(1);

        downloadBytes(result.data, result.name);
        const info = C.inspectBlob(blob);
        renderResult(
          [
            ["اسم الملف بعد فك التشفير", result.name, true],
            ["حجم البيانات المفكوكة", formatBytes(result.data.length), true],
            ["الحجم المشفّر", formatBytes(blob.length), true],
            ["الخوارزمية", info.algorithm, false],
            ["اشتقاق المفتاح", info.kdf, false],
            info.iterations ? ["عدد التكرارات", info.iterations.toLocaleString("en-US"), false] : null,
            ["زمن فك التشفير", `${elapsed} ثانية`, true],
          ].filter(Boolean),
          "✅ تم استرجاع الملف بنجاح"
        );
        showSuccess(`جاهز للتنزيل: ${result.name}`);
      } catch (err) {
        showError(err && err.message ? err.message : String(err));
      }
    });
  }

  /* --------------------------------------------------------------- توليد مفتاح */
  const keygenForm = $("#form-keygen");
  if (keygenForm) {
    keygenForm.addEventListener("submit", async (event) => {
      event.preventDefault();
      clearMessages();
      try {
        const length = Number($("#keygen-length").value);
        const key = await setBusy($("#btn-keygen"), true, "جارٍ التوليد…", () => C.generateKeyBytes(length));
        const body = new Uint8Array(
          new TextEncoder().encode(
            "# مفتاح «الخزنة» — احتفظ به في مكان آمن ولا تشاركه مع أحد.\n"
            + "# من يملك هذا الملف يستطيع فك تشفير ملفاتك.\n"
            + C.bytesToBase64(key) + "\n"
          )
        );
        downloadBytes(body, "safebox.key", "text/plain");
        renderResult(
          [
            ["طول المفتاح", `${length * 8} بت`, false],
            ["عدد البايتات", String(length), false],
            ["الاسم", "safebox.key", true],
          ],
          "✅ تم توليد المفتاح",
          "خزّن المفتاح في مكان آمن ومنفصل عن ملفاتك المشفّرة."
        );
        showSuccess("جاهز للتنزيل: safebox.key");
      } catch (err) {
        showError(err && err.message ? err.message : String(err));
      }
    });
  }

  /* --------------------------------------------------------------- تشفير نص */
  const textOutput = $("#text-output");
  const textBtn = $("#btn-text-run");
  const textMode = () => {
    const checked = $("input[name=text_mode]:checked");
    return checked ? checked.value : "encrypt";
  };

  function syncTextTab() {
    const mode = textMode();
    const encrypt = mode === "encrypt";
    textBtn.textContent = encrypt ? "🔒 شفّر إلى نص" : "🔓 فكّ النص المشفّر";
    $("#text-input-label").textContent = encrypt ? "النص الذي تريد تشفيره" : "النص المشفّر (Base64)";
    $("#text-input").placeholder = encrypt
      ? "اكتب النص السري هنا (رسالة، كلمة مرور، رابط…)"
      : "الصق النص المشفّر (Base64) الذي أنتجته سابقاً…";
    $("#text-input-hint").textContent = encrypt
      ? "الناتج سيكون نص Base64 طويل — انسخه كاملاً واحفظه مع كلمة المرور."
      : "سنفكّ النص باستخدام كلمة المرور نفسها المستخدمة عند التشفير.";
    $("#text-output-label").textContent = encrypt ? "النص المشفّر" : "النص الأصلي";
    $("#text-result-field").hidden = true;
    textOutput.value = "";
  }

  $$("input[name=text_mode]").forEach((radio) => radio.addEventListener("change", syncTextTab));
  syncTextTab();

  if (textBtn) {
    textBtn.addEventListener("click", async () => {
      clearMessages();
      const text = $("#text-input").value;
      const password = $("#text-password").value;
      const encrypt = textMode() === "encrypt";

      if (!text.trim()) {
        showError(encrypt ? "اكتب النص أولاً." : "الصق النص المشفّر أولاً.");
        return;
      }
      if (!password) { showError("أدخل كلمة المرور."); return; }
      if (encrypt && new TextEncoder().encode(text).length > C.MAX_TEXT_BYTES) {
        showError("النص طويل جداً (الحد 64 كيلوبايت).");
        return;
      }

      try {
        const value = await setBusy(textBtn, true, encrypt ? "جارٍ التشفير…" : "جارٍ فك التشفير…", () =>
          encrypt
            ? C.encryptText(text, { password, preset: "balanced" })
            : C.decryptText(text, { password })
        );
        $("#text-result-field").hidden = false;
        textOutput.value = value;
        showSuccess(encrypt ? "تم التشفير — انسخ النص كاملاً." : "تم فك التشفير.");
      } catch (err) {
        showError(err && err.message ? err.message : String(err));
      }
    });
  }

  const btnCopy = $("#btn-copy-text");
  if (btnCopy) {
    btnCopy.addEventListener("click", async () => {
      try {
        await navigator.clipboard.writeText(textOutput.value);
        btnCopy.textContent = "✅ تم النسخ";
      } catch (_err) {
        textOutput.select();
        document.execCommand("copy");
        btnCopy.textContent = "✅ تم النسخ";
      }
      setTimeout(() => { btnCopy.textContent = "📋 نسخ النتيجة"; }, 1800);
    });
  }

  /* --------------------------------------------------------------- فحص الدعم */
  try {
    C.requireCrypto();
  } catch (_err) {
    $("#crypto-warning").hidden = false;
  }
})();
