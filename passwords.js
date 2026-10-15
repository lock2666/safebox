/*!
 * passwords.js — تقييم قوة كلمة المرور + المولّد (نسخة متوافقة مع Python).
 */
(() => {
  "use strict";

  const COMMON_PASSWORDS = new Set([
    "123456", "123456789", "12345678", "12345", "1234567", "password", "password1",
    "1234567890", "qwerty", "abc123", "111111", "iloveyou", "admin", "letmein",
    "welcome", "monkey", "dragon", "000000", "sunshine", "princess", "football",
    "starwars", "qwerty123", "passw0rd", "alzaeem", "احمد رسول", "555555",
  ]);

  const LEVELS = [
    [60, "قوية جداً", "#22c55e"],
    [48, "قوية", "#4ade80"],
    [36, "جيدة", "#facc15"],
    [28, "متوسطة", "#fb923c"],
    [0, "ضعيفة", "#ef4444"],
  ];

  function poolSize(password) {
    let pool = 0;
    if (/[a-z]/.test(password)) pool += 26;
    if (/[A-Z]/.test(password)) pool += 26;
    if (/[0-9]/.test(password)) pool += 10;
    if (/[^A-Za-z0-9]/.test(password)) pool += 33;
    if (/[^\x00-\x7F]/.test(password)) pool += 500; // تقدير سخي للعربية
    return pool;
  }

  function estimateStrength(password) {
    if (!password) return { score: 0, level: "فارغة", color: "#64748b", bits: 0, suggestions: ["أدخل كلمة مرور."] };

    const suggestions = [];
    const pool = poolSize(password);
    const bits = pool > 1 ? password.length * Math.log2(pool) : 0;
    const lower = password.toLowerCase();

    if (COMMON_PASSWORDS.has(lower)) {
      return {
        score: 0, level: "ضعيفة جداً", color: "#ef4444", bits: 8,
        suggestions: ["هذه من أشهر كلمات المرور المخترقة — لا تستخدمها أبداً."],
      };
    }
    for (const common of COMMON_PASSWORDS) {
      if (common.length >= 4 && lower.includes(common)) {
        suggestions.push("تتضمن كلمة مرور شائعة — تجنّبها.");
        break;
      }
    }
    if (new Set(password).size <= 2) suggestions.push("تستخدم حرفين فقط مكرّرين — تنويع أكبر.");
    if (/^\d+$/.test(password)) suggestions.push("أرقام فقط — أضف حروفاً ورموزاً.");
    if (/^[A-Za-z]+$/.test(password)) suggestions.push("حروف فقط — أضف أرقاماً ورموزاً.");
    if (/(.)\1{2,}/.test(password)) suggestions.push("توجد تكرارات متتالية (aaa, 111).");
    for (const [seq, label] of [
      ["0123456789", "أرقاماً متسلسلة"],
      ["abcdefghijklmnopqrstuvwxyz", "حروفاً متسلسلة"],
      ["qwertyuiop", "صفاً من لوحة المفاتيح"],
    ]) {
      if (lower.includes(seq.slice(0, 6))) suggestions.push(`تتضمن ${label} — تجنّب التسلسل.`);
    }
    if (password.length < 12) suggestions.push("الطول الأفضل 16 حرفاً على الأقل.");
    if (!/[a-z]/.test(password) || !/[A-Z]/.test(password)) {
      suggestions.push("اخلط بين الأحرف الكبيرة والصغيرة.");
    }

    let score = 0;
    for (let i = 0; i < LEVELS.length; i += 1) {
      if (bits >= LEVELS[i][0]) { score = LEVELS.length - 1 - i; break; }
    }
    if (password.length >= 16 && new Set(password).size >= 10) score = Math.min(4, score + 1);
    if (suggestions.length) score = Math.max(0, score - 1);

    const [level, color] = [LEVELS[LEVELS.length - 1 - score][1], LEVELS[LEVELS.length - 1 - score][2]];
    if (!suggestions.length) suggestions.push("لا اقتراحات — كلمة مرور ممتازة.");
    return { score, level, color, bits: Math.round(bits * 10) / 10, suggestions };
  }

  function generatePassword(length = 20) {
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*-_=+?";
    const values = crypto.getRandomValues(new Uint32Array(length));
    let password;
    do {
      password = "";
      for (let i = 0; i < length; i += 1) {
        password += alphabet[values[i] % alphabet.length];
      }
    } while (!(
      /[a-z]/.test(password) && /[A-Z]/.test(password)
      && /[0-9]/.test(password) && /[!@#$%^&*\-_=+?]/.test(password)
    ));
    return password;
  }

  window.SafeBoxPasswords = { estimateStrength, generatePassword };
})();
