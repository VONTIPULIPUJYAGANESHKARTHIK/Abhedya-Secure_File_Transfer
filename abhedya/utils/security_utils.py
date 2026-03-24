"""utils/security_utils.py — Password strength & secure generation"""
from __future__ import annotations
import math, re, secrets, string
from dataclasses import dataclass
from typing import List


@dataclass
class PwReport:
    entropy: float
    score: int          # 0-100  for progress bar
    label: str
    color: str
    crack_time: str
    issues: List[str]
    suggestions: List[str]


def analyse(pw: str) -> PwReport:
    issues, hints = [], []

    if len(pw) < 8:
        issues.append("Too short — use at least 8 characters.")
    elif len(pw) < 12:
        hints.append("Increase to 12+ characters for stronger security.")

    has_l = bool(re.search(r"[a-z]", pw))
    has_u = bool(re.search(r"[A-Z]", pw))
    has_d = bool(re.search(r"\d", pw))
    has_s = bool(re.search(r"[^a-zA-Z0-9]", pw))

    if not has_l: hints.append("Add lowercase letters.")
    if not has_u: hints.append("Add uppercase letters.")
    if not has_d: hints.append("Add numbers.")
    if not has_s: hints.append("Add symbols (!@#$…) for much higher entropy.")

    if re.search(r"(.)\1{2,}", pw):
        issues.append("Repeated characters reduce entropy.")
    if pw.lower() in {"password","123456","qwerty","letmein","admin","welcome","abcdef","111111"}:
        issues.append("This is a commonly breached password.")

    charset = sum([26*has_l, 26*has_u, 10*has_d, 32*has_s]) or 1
    ent     = len(pw) * math.log2(charset)

    if   ent < 28:  score, label, color = 8,  "Very Weak",   "#ef4444"
    elif ent < 40:  score, label, color = 25, "Weak",        "#f97316"
    elif ent < 55:  score, label, color = 50, "Moderate",    "#eab308"
    elif ent < 72:  score, label, color = 78, "Strong",      "#22c55e"
    else:           score, label, color = 97, "Very Strong", "#06b6d4"

    secs = (2 ** ent) / 1e9 / 2
    if   secs < 60:          crack = "Instant"
    elif secs < 3_600:       crack = "Minutes"
    elif secs < 86_400:      crack = "Hours"
    elif secs < 2_592_000:   crack = "Days"
    elif secs < 31_536_000:  crack = "Months"
    elif secs < 3.15e8:      crack = "Years"
    else:                    crack = "Centuries"

    return PwReport(entropy=round(ent, 1), score=score, label=label,
                    color=color, crack_time=crack, issues=issues, suggestions=hints)


def generate_password(length: int = 20) -> str:
    length = max(12, min(length, 64))
    alpha  = string.ascii_letters + string.digits + "!@#$%^&*()-_=+[]{}|;:,.<>?"
    forced = [
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.digits),
        secrets.choice("!@#$%^&*()-_"),
    ]
    rest = [secrets.choice(alpha) for _ in range(length - 4)]
    pool = forced + rest
    secrets.SystemRandom().shuffle(pool)
    return "".join(pool)
