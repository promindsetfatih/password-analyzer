"""
╔══════════════════════════════════════════════════════════╗
║     PASSWORD STRENGTH ANALYZER — Flask Web App           ║
║          by Fatih Bilekyigit | Codemasters 2026           ║
╚══════════════════════════════════════════════════════════╝

Çalıştırmak için terminalde:
    pip install flask
    python app.py

Tarayıcıda aç:
    http://127.0.0.1:5000
"""

import re
import math
from flask import Flask, render_template, request, jsonify

app = Flask(__name__)


def check_length(password):
    length = len(password)
    if length < 6:   return 0, f"Too short ({length} chars) — minimum 8 recommended"
    elif length < 8:  return 1, f"Short ({length} chars) — aim for at least 12"
    elif length < 12: return 2, f"Acceptable length ({length} chars)"
    elif length < 16: return 3, f"Good length ({length} chars)"
    else:             return 4, f"Excellent length ({length} chars)"


def check_character_variety(password):
    has_lower   = bool(re.search(r'[a-z]', password))
    has_upper   = bool(re.search(r'[A-Z]', password))
    has_digit   = bool(re.search(r'\d', password))
    has_special = bool(re.search(r'[^a-zA-Z0-9]', password))
    checks = [
        (has_lower,   "Lowercase letters (a–z)"),
        (has_upper,   "Uppercase letters (A–Z)"),
        (has_digit,   "Numbers (0–9)"),
        (has_special, "Special characters (!@#$...)"),
    ]
    score = sum(1 for ok, _ in checks if ok)
    return score, checks, has_lower, has_upper, has_digit, has_special


def check_patterns(password):
    common = ["password","123456","qwerty","abc123","letmein","welcome","admin","iloveyou","monkey","dragon"]
    lp = password.lower()
    penalty = 0
    is_common  = any(c in lp for c in common)
    has_seqnum = bool(re.search(r'012|123|234|345|456|567|678|789', password))
    has_seqlet = bool(re.search(r'abc|bcd|qwe|ert|asd', lp))
    has_repeat = bool(re.search(r'(.)\1{2,}', password))
    has_kbd    = bool(re.search(r'qwerty|asdfgh|zxcvbn', lp))
    if is_common:  penalty += 2
    if has_seqnum: penalty += 1
    if has_seqlet: penalty += 1
    if has_repeat: penalty += 1
    if has_kbd:    penalty += 1
    patterns = [
        (not is_common,  "Common password detected"      if is_common  else "Not a common password"),
        (not has_seqnum, "Sequential numbers (123...)"   if has_seqnum else "No sequential numbers"),
        (not has_seqlet, "Sequential letters (abc...)"   if has_seqlet else "No sequential letters"),
        (not has_repeat, "Repeated characters (aaa...)"  if has_repeat else "No repeated characters"),
        (not has_kbd,    "Keyboard pattern (qwerty...)"  if has_kbd    else "No keyboard patterns"),
    ]
    return penalty, patterns


def calculate_entropy(password):
    charset = 0
    if re.search(r'[a-z]', password):       charset += 26
    if re.search(r'[A-Z]', password):       charset += 26
    if re.search(r'\d',    password):       charset += 10
    if re.search(r'[^a-zA-Z0-9]', password): charset += 32
    return round(len(password) * math.log2(charset), 1) if charset else 0.0


def estimate_crack_time(entropy):
    s = (2 ** entropy) / 10_000_000_000
    if s < 1:             return "Instantly"
    if s < 60:            return f"{int(s)} seconds"
    if s < 3600:          return f"{int(s/60)} minutes"
    if s < 86400:         return f"{int(s/3600)} hours"
    if s < 2_592_000:     return f"{int(s/86400)} days"
    if s < 31_536_000:    return f"{int(s/2_592_000)} months"
    if s < 3_153_600_000: return f"{int(s/31_536_000)} years"
    return "Centuries"


def get_strength_label(score):
    if score <= 2: return "Very weak",   "danger"
    if score <= 4: return "Weak",        "warning"
    if score <= 6: return "Moderate",    "info"
    if score <= 8: return "Strong",      "success"
    return               "Very strong", "teal"


def get_grade(score):
    return {0:"D",1:"D",2:"D",3:"C",4:"C",5:"B",6:"B",7:"A",8:"A"}.get(score, "A+")


def generate_tips(score, has_special, has_upper, has_digit, length):
    tips = []
    if length < 12:     tips.append("Use at least 12 characters — longer is always safer")
    if not has_special: tips.append("Add special characters like @, #, !, $ to boost strength")
    if not has_upper:   tips.append("Mix uppercase and lowercase letters")
    if not has_digit:   tips.append("Add numbers to increase complexity")
    if score < 7:       tips.append('Try a passphrase: "Coffee!Jazz#Utrecht2026"')
    if score >= 8:      tips.append("Great password! Use a unique one for each account")
    tips.append("Use a password manager to store complex passwords safely")
    tips.append("Change your passwords every 6–12 months")
    return tips


def analyze_password(password):
    len_score, len_msg = check_length(password)
    var_score, char_checks, has_lower, has_upper, has_digit, has_special = check_character_variety(password)
    penalty, patterns = check_patterns(password)
    entropy    = calculate_entropy(password)
    crack_time = estimate_crack_time(entropy)
    score      = max(0, min(10, round(len_score + var_score * 1.5 - penalty)))
    label, level = get_strength_label(score)
    return {
        "score":       score,
        "label":       label,
        "level":       level,
        "grade":       get_grade(score),
        "entropy":     entropy,
        "crack_time":  crack_time,
        "length":      len(password),
        "char_types":  var_score,
        "len_msg":     len_msg,
        "char_checks": [{"ok": ok, "text": txt} for ok, txt in char_checks],
        "patterns":    [{"ok": ok, "text": txt} for ok, txt in patterns],
        "tips":        generate_tips(score, has_special, has_upper, has_digit, len(password)),
    }


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze():
    data     = request.get_json()
    password = data.get("password", "")
    if not password:
        return jsonify({"error": "No password provided"}), 400
    return jsonify(analyze_password(password))


if __name__ == "__main__":
    print("\n🔐 Password Analyzer → http://127.0.0.1:5000\n")
    app.run()
