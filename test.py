import json
import chardet

# --- Config --------------------------------------------------------------
semgrep_file = "results.json"
expected_file = "test.txt"

# --- Detect encoding for Semgrep JSON ------------------------------------
with open(semgrep_file, "rb") as f:
    raw = f.read()

encoding = chardet.detect(raw)["encoding"]
print(f"[*] Detected encoding: {encoding}")

# --- Load JSON safely ----------------------------------------------------
try:
    if encoding and "UTF-16" in encoding.upper():
        data = json.loads(raw.decode("utf-16"))
    else:
        data = json.loads(raw.decode(encoding or "utf-8"))
except Exception as e:
    print(f"[!] Error reading {semgrep_file}: {e}")
    exit(1)

# --- Load expected vulnerabilities --------------------------------------
with open(expected_file, "r", encoding="utf-8") as f:
    expected = [line.strip().lower() for line in f if line.strip()]

# --- Extract all rule messages or IDs from Semgrep output ----------------
found = set()
if "results" in data:
    for r in data["results"]:
        msg = r.get("check_id") or r.get("extra", {}).get("message", "")
        if msg:
            found.add(msg.lower())
else:
    # handle semgrep CLI output structure (if only results array)
    for r in data:
        if isinstance(r, dict):
            msg = r.get("check_id") or r.get("extra", {}).get("message", "")
            if msg:
                found.add(msg.lower())

# --- Match and Compare ---------------------------------------------------
tp = set()
for e in expected:
    if any(e in f for f in found):
        tp.add(e)

fp = [f for f in found if not any(e in f for e in expected)]
fn = [e for e in expected if not any(e in f for f in found)]

# --- Calculate Metrics ---------------------------------------------------
precision = len(tp) / (len(tp) + len(fp)) if (len(tp) + len(fp)) > 0 else 0
recall = len(tp) / (len(tp) + len(fn)) if (len(tp) + len(fn)) > 0 else 0
accuracy = len(tp) / len(expected) if expected else 0

# --- Print Results -------------------------------------------------------
print("\n🔍 Semgrep Vulnerability Detection Accuracy")
print("---------------------------------------------")
print(f"True Positives (TP): {len(tp)}")
print(f"False Positives (FP): {len(fp)}")
print(f"False Negatives (FN): {len(fn)}")
print(f"\n✅ Precision: {precision:.2f}")
print(f"🎯 Recall:    {recall:.2f}")
print(f"📊 Accuracy:  {accuracy:.2f}\n")

print("Matched Vulnerabilities:")
for v in tp:
    print(f"  ✔ {v}")

print("\nMissed Vulnerabilities:")
for v in fn:
    print(f"  ✖ {v}")

print("\nExtra (False Positives):")
for v in fp:
    print(f"  ⚠ {v}")
