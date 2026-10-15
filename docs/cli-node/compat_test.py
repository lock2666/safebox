# -*- coding: utf-8 -*-
"""توافق Python ↔ Node.js: يفتح ملفاً شفّره Node ويشفّر ملفاً ليفتحه Node."""
import base64
import io
import subprocess
import sys

sys.path.insert(0, r"C:\Users\R\Desktop\abood\safebox")
import crypto_core as cc

NODE = r"C:\Users\R\AppData\Local\Temp\nodejs\node-v22.11.0-win-x64\node.exe"
CLI_NODE = r"docs\cli-node\node.js"
PW = "Xk9#mQ2vLp7$Wz4!Rt8^Bn6&"
TMP = __import__("os").environ.get("TEMP", r"C:\Users\R\AppData\Local\Temp")

original = "ملف شفّرته نسخة Node.js وسيفتحه Python ✅ " + "x" * 400
src = rf"{TMP}\compat_src.txt"
with io.open(src, "w", encoding="utf-8") as fh:
    fh.write(original)


def run_node(args):
    return subprocess.run([NODE, CLI_NODE, *args], capture_output=True, text=True,
                          encoding="utf-8", cwd=r"C:\Users\R\Desktop\abood\safebox")


ok = True

# --- 1) Node يشفر -> Python يفك ---
sbox = rf"{TMP}\compat_node.sbox"
r = run_node(["encrypt", src, "-p", PW, "-o", sbox, "--force"])
assert r.returncode == 0, r.stderr
print("1) Node encrypt OK")

result = cc.decrypt_bytes(io.open(sbox, "rb").read(), password=PW)
text = result.data.decode("utf-8")
match1 = text == original
print(f"   Python decrypt: {'ناجح ✅' if match1 else 'فاشل ❌'} (name={result.name})")
ok = ok and match1

# --- 2) Python يشفر -> Node يفك ---
sbox2 = rf"{TMP}\compat_py.sbox"
cc.encrypt_bytes(original.encode("utf-8"), password=PW, preset="fast",
                 filename="compat_src.txt")
with io.open(sbox2, "wb") as fh:
    fh.write(cc.encrypt_bytes(original.encode("utf-8"), password=PW,
                              preset="fast", filename="compat_src.txt"))
print("2) Python encrypt OK")

out2 = rf"{TMP}\compat_node_out.txt"
r = run_node(["decrypt", sbox2, "-p", PW, "-o", out2, "--force"])
assert r.returncode == 0, r.stderr
match2 = io.open(out2, encoding="utf-8").read() == original
print(f"   Node decrypt: {'ناجح ✅' if match2 else 'فاشل ❌'}")
ok = ok and match2

# --- 3) ملف مفتاح: Python يولّد -> Node يشفّر -> Python يفك ---
key = cc.generate_key()
key_file = rf"{TMP}\compat.key"
with io.open(key_file, "w", encoding="utf-8") as fh:
    fh.write("# مفتاح توافق\n" + base64.urlsafe_b64encode(key).decode() + "\n")

sbox3 = rf"{TMP}\compat_key.sbox"
r = run_node(["encrypt", src, "-k", key_file, "-o", sbox3, "--force"])
assert r.returncode == 0, r.stderr
result3 = cc.decrypt_bytes(io.open(sbox3, "rb").read(), key=key)
match3 = result3.data.decode("utf-8") == original
print(f"3) Key file Node->Python: {'ناجح ✅' if match3 else 'فاشل ❌'}")
ok = ok and match3

# --- 4) نص: Python يشفر -> Node يفك ---
token = cc.encrypt_text("رسالة توافق نصية", password=PW, preset="fast")
r = run_node(["text", "-t", token, "-p", PW])
match4 = "رسالة توافق نصية" in r.stdout
print(f"4) Text Python->Node: {'ناجح ✅' if match4 else 'فاشل ❌'}")
ok = ok and match4

print("\n>>> التوافق الكامل بين Python و Node.js:",
      "ناجح ✅" if ok else "فاشل ❌")
sys.exit(0 if ok else 1)
