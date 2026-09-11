import json
import os
import re
from pathlib import Path

# ---- Regex patterns ----

# Email: local@domain.tld, rejects loose "match everything" shapes
EMAIL_PATTERN = re.compile(
    r"[A-Za-z0-9](?:[A-Za-z0-9._%+-]*[A-Za-z0-9])?"
    r"@"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)+"
)

# ALU-specific domain classification (case-insensitive: aluEducation.com still matches)
ALU_DOMAIN_PATTERNS = {
    "ALU official": re.compile(r"@alueducation\.com$", re.IGNORECASE),
    "ALU alumni": re.compile(r"@alumni\.alueducation\.com$", re.IGNORECASE),
    "ALU SI": re.compile(r"@si\.alueducation\.com$", re.IGNORECASE),
}

# Credit card: 13-19 digits, grouped with spaces/hyphens (shape only, validated separately)
CREDIT_CARD_PATTERN = re.compile(r"\b(?:\d[ -]?){13,19}\b")

# Phone: optional country code + optional (area code) + grouped digits or one unbroken run
PHONE_PATTERN = re.compile(
    r"(?:\+\d{1,3}[ -]?)?"
    r"(?:\(\d{2,4}\)[ -]?)?"
    r"(?:"
    r"(?:\d{2,4}[ -]){1,4}\d{2,4}"
    r"|"
    r"\d{7,13}"
    r")"
)

# URL: http/https/ftp schemes
URL_PATTERN = re.compile(
    r"(?:https?|ftp)://[A-Za-z0-9.-]+(?:\.[A-Za-z]{2,})(?::\d+)?(?:/[^\s<>\"']*)?"
)

# ---- Security: never trust input as code, and never expose raw card numbers ----

SUSPICIOUS_PATTERNS = [
    re.compile(r"<\s*script", re.IGNORECASE),
    re.compile(r"drop\s+table", re.IGNORECASE),
    re.compile(r"union\s+select", re.IGNORECASE),
    re.compile(r"'\s*or\s*'?1'?\s*=\s*'?1", re.IGNORECASE),
    re.compile(r";\s*--\s*$"),
    re.compile(r"<\s*[a-z]+[^>]*on\w+\s*="),
]


def is_hostile_line(line: str) -> bool:
    # Flags known XSS/SQL-injection signatures so that line is skipped entirely
    return any(pattern.search(line) for pattern in SUSPICIOUS_PATTERNS)


def luhn_valid(digits: str) -> bool:
    total = 0
    reverse_digits = digits[::-1]
    for i, ch in enumerate(reverse_digits):
        n = int(ch)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def mask_card(digits: str) -> str:
    # Card numbers are still masked in the output -- only the last 4 digits
    # are ever shown, even though email addresses in this build are shown
    # in full per an explicit request from the submission owner.
    last4 = digits[-4:]
    groups = ["****"] * ((len(digits) - 4) // 4)
    if (len(digits) - 4) % 4:
        groups.append("*" * ((len(digits) - 4) % 4))
    return " ".join(groups + [last4])


# ---- Extraction ----

def extract_emails(text: str):
    results = []
    for line in text.splitlines():
        if is_hostile_line(line):
            continue
        for match in EMAIL_PATTERN.finditer(line):
            email = match.group(0)
            if ".." in email or email.startswith(".") or email.endswith("."):
                continue
            email_type = "external"
            for label, pattern in ALU_DOMAIN_PATTERNS.items():
                if pattern.search(email):
                    email_type = label
                    break
            results.append({"email": email, "type": email_type})
    seen = set()
    unique = []
    for item in results:
        if item["email"] not in seen:
            seen.add(item["email"])
            unique.append(item)
    return unique


def extract_credit_cards(text: str):
    results = []
    for line in text.splitlines():
        if is_hostile_line(line):
            continue
        for match in CREDIT_CARD_PATTERN.finditer(line):
            digits = re.sub(r"[ -]", "", match.group(0))
            if not (13 <= len(digits) <= 19):
                continue
            results.append({
                "masked": mask_card(digits),
                "valid_luhn": luhn_valid(digits),
            })
    return results


def extract_phone_numbers(text: str):
    results = []
    for line in text.splitlines():
        if is_hostile_line(line):
            continue
        for match in PHONE_PATTERN.finditer(line):
            raw = match.group(0).strip()
            digit_count = len(re.sub(r"\D", "", raw))
            if not (9 <= digit_count <= 13):
                continue
            results.append(raw)
    return list(dict.fromkeys(results))


def extract_urls(text: str):
    results = []
    for line in text.splitlines():
        if is_hostile_line(line):
            continue
        for match in URL_PATTERN.finditer(line):
            url = match.group(0).rstrip(').,')
            results.append(url)
    return list(dict.fromkeys(results))


def find_rejected_lines(text: str):
    # Generic message only -- the matched content itself is never echoed
    # back into the output, so an injection payload never gets a second
    # trip through anything that renders or logs this report.
    return [
        "Line skipped: injection pattern detected"
        for line in text.splitlines()
        if is_hostile_line(line)
    ]


def main():
    base_dir = Path(__file__).resolve().parent.parent
    input_path = base_dir / "input" / "raw-text.txt"
    output_path = base_dir / "output" / "sample-output.json"

    if not input_path.exists():
        raise FileNotFoundError(f"Expected input file at {input_path}")

    raw_text = input_path.read_text(encoding="utf-8")

    report = {
        "emails": extract_emails(raw_text),
        "credit_cards": extract_credit_cards(raw_text),
        "urls": extract_urls(raw_text),
        "phones": extract_phone_numbers(raw_text),
        "rejected_lines": find_rejected_lines(raw_text),
    }

    os.makedirs(output_path.parent, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    print("=== Extraction Summary ===")
    print(f"Emails found:        {len(report['emails'])}")
    for e in report["emails"]:
        print(f"  - {e['email']}  [{e['type']}]")
    print(f"Credit cards found:  {len(report['credit_cards'])}")
    for c in report["credit_cards"]:
        status = "VALID (Luhn)" if c["valid_luhn"] else "INVALID (failed Luhn check)"
        print(f"  - {c['masked']}  ({status})")
    print(f"URLs found:          {len(report['urls'])}")
    for u in report["urls"]:
        print(f"  - {u}")
    print(f"Phones found:        {len(report['phones'])}")
    for p in report["phones"]:
        print(f"  - {p}")
    print(f"Rejected lines:      {len(report['rejected_lines'])}")

    print(f"\nFull report written to {output_path}")


if __name__ == "__main__":
    main()
