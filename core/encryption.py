import json
from collections import Counter
from datetime import datetime
from pathlib import Path

DEFAULT_MAPPING = {
    "A": "ව", "B": "ක", "C": "ග", "D": "ස", "E": "න",
    "F": "ම", "G": "ර", "H": "ත", "I": "ද", "J": "ප",
    "K": "ල", "L": "ය", "M": "බ", "N": "හ", "O": "ජ",
    "P": "ට", "Q": "ඩ", "R": "ච", "S": "ඡ", "T": "ඤ",
    "U": "ණ", "V": "ථ", "W": "ධ", "X": "භ", "Y": "ශ",
    "Z": "ෂ",
}

BASE_PATH = Path(__file__).resolve().parent.parent
MAPPING_FILE = BASE_PATH / "language_mapping.json"
AUDIT_LOG_FILE = BASE_PATH / "security_audit.log"


def log_security_event(username: str, role: str, action: str, detail: str = "") -> None:
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    entry = f"[{timestamp}] USER={username} | ROLE={role} | ACTION={action}"
    if detail:
        entry += f" | {detail}"
    try:
        with AUDIT_LOG_FILE.open("a", encoding="utf-8") as fp:
            fp.write(entry + "\n")
    except OSError:
        pass


def read_audit_logs(limit: int = 200) -> str:
    if not AUDIT_LOG_FILE.exists():
        return "No security audit events recorded yet."
    try:
        lines = AUDIT_LOG_FILE.read_text(encoding="utf-8").splitlines()
        return "\n".join(lines[-limit:]) if lines else "No security audit events recorded yet."
    except OSError:
        return "Unable to read audit log."


def load_mapping():
    if not MAPPING_FILE.exists():
        return DEFAULT_MAPPING.copy()
    try:
        data = json.loads(MAPPING_FILE.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            return DEFAULT_MAPPING.copy()
        mapping = {str(k): str(v) for k, v in data.items()}
        return mapping if not validate_mapping(mapping) else DEFAULT_MAPPING.copy()
    except (OSError, json.JSONDecodeError, TypeError, ValueError):
        return DEFAULT_MAPPING.copy()


def save_mapping(mapping):
    MAPPING_FILE.write_text(
        json.dumps(mapping, ensure_ascii=False, indent=4),
        encoding="utf-8"
    )


def validate_mapping(mapping):
    if not mapping:
        return "Add at least one character mapping."

    keys = list(mapping.keys())
    values = [str(value).strip() for value in mapping.values()]

    if any(not str(key).strip() for key in keys):
        return "Original characters cannot be empty."
    if any(not value for value in values):
        return "Your replacement characters cannot be empty."
    if len(set(keys)) != len(keys):
        return "Each original character must be unique."
    if len(set(values)) != len(values):
        return "Each replacement must be unique so decryption works."

    return ""


def _build_lookup(mapping):
    lookup = dict(mapping)
    for key, value in mapping.items():
        if len(key) == 1 and key.isalpha():
            lower_key = key.lower()
            upper_key = key.upper()
            if lower_key not in lookup:
                lookup[lower_key] = value
            if upper_key not in lookup:
                lookup[upper_key] = value
    return lookup


def _replace_longest_first(text, mapping):
    tokens = sorted(mapping.keys(), key=len, reverse=True)
    result = []
    i = 0
    while i < len(text):
        match = next((token for token in tokens if text.startswith(token, i)), None)
        if match is None:
            result.append(text[i])
            i += 1
        else:
            result.append(mapping[match])
            i += len(match)
    return "".join(result)


def encrypt_text(text, mapping):
    return _replace_longest_first(text, _build_lookup(mapping))


def decrypt_text(text, mapping):
    reverse = {value: key for key, value in mapping.items()}
    return _replace_longest_first(text, reverse)


def analyze_message(text: str, mapping: dict) -> dict:
    """Perform cryptographic/linguistic frequency and coverage analysis for Analysts."""
    total_chars = len(text)
    non_space_chars = sum(1 for ch in text if not ch.isspace())
    words = text.split()
    lines = text.splitlines() if text else []

    lookup = _build_lookup(mapping)
    reverse = {v: k for k, v in mapping.items()}

    matched_plain = 0
    matched_cipher = 0
    unmapped_chars = Counter()

    i = 0
    plain_tokens = sorted(lookup.keys(), key=len, reverse=True)
    while i < len(text):
        m = next((t for t in plain_tokens if text.startswith(t, i)), None)
        if m:
            matched_plain += len(m)
            i += len(m)
        else:
            if not text[i].isspace():
                unmapped_chars[text[i]] += 1
            i += 1

    i = 0
    cipher_tokens = sorted(reverse.keys(), key=len, reverse=True)
    while i < len(text):
        m = next((t for t in cipher_tokens if text.startswith(t, i)), None)
        if m:
            matched_cipher += len(m)
            i += len(m)
        else:
            i += 1

    visible_chars = [ch for ch in text if not ch.isspace()]
    freq = Counter(visible_chars)
    top_symbols = freq.most_common(10)

    if matched_cipher > matched_plain:
        detected_mode = "Ciphertext (Encrypted Language)"
    elif matched_plain > 0:
        detected_mode = "Plaintext (Unencrypted Source)"
    else:
        detected_mode = "Neutral / Symbols Only"

    coverage_pct = round((max(matched_plain, matched_cipher) / non_space_chars) * 100, 1) if non_space_chars else 0.0

    return {
        "detected_mode": detected_mode,
        "total_chars": total_chars,
        "non_space_chars": non_space_chars,
        "word_count": len(words),
        "line_count": len(lines),
        "unique_symbols": len(freq),
        "coverage_pct": coverage_pct,
        "top_symbols": top_symbols,
        "unmapped_chars": unmapped_chars.most_common(8),
    }
