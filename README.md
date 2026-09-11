# Data Extraction & Secure Validation Assignment

**Author:** Balinda Sonia (s.balinda1@alustudent.com)

A regex-based Python program that extracts structured data from raw,
messy, production-style text, while treating all input as untrusted.

## Data types implemented

1. Email addresses (with ALU-specific domain classification) — required
2. Credit card numbers (with Luhn checksum validation) — required
3. Phone numbers
4. URLs (with basic phishing-pattern flagging)
5. Hashtags

## How to run

```bash
cd alu-regex-data-extraction_BalindaSonia
python src/main.py
```

Python 3.8+, standard library only. Reads `input/raw-text.txt`, writes
`output/sample-output.json` and prints a masked console summary.

## Input data

`input/raw-text.txt` is five fictional support tickets written to look
like real production text — mixed phone formats, ALU/alumni/SI/external
emails, two credit cards (one deliberately invalid), a phishing-style
link, hashtags, and two hidden attack payloads (an XSS `<script>` tag
and a SQL-injection string) planted among the ordinary tickets.

## Regex patterns

- **Emails** — practical `local@domain.tld` shape, rejects consecutive
  dots and leading/trailing dots.
- **ALU classification** — checks the matched email's domain against
  `@alueducation.com`, `@alumni.alueducation.com`, `@si.alueducation.com`
  and labels it `alu_official` / `alu_alumni` / `alu_si` / `external`.
- **Credit cards** — matches 13–19 digit runs grouped in 4s; every match
  is then run through a Luhn checksum to flag which are numerically
  plausible.
- **Phone numbers** — optional `+countrycode`, optional `(area code)`,
  then either separated digit groups or one unbroken digit run, filtered
  to 9–13 total digits.
- **URLs** — standard `http(s)://` matcher; flags `.tk` domains or
  `pass=`/`password=`/`token=` query params as suspicious.
- **Hashtags** — `#` + letter + word characters, with a lookbehind so it
  doesn't match mid-word.

## Security considerations

- Extracted text is data, never executed or interpolated into a
  command/query.
- Every line is checked against known attack signatures (`<script`,
  `DROP TABLE`, `UNION SELECT`, `' OR '1'='1`, inline event-handler
  attributes) before extraction runs; matching lines are excluded and
  logged separately under `flagged_hostile_lines`.
- Shape alone isn't trusted — credit-card-looking strings must also pass
  a Luhn check; malformed emails are rejected even if the base pattern
  matches.
- Sensitive data is masked (`************1234`, `j*********@domain.com`)
  before it's ever written to console or JSON — raw values are never
  persisted.
- Not a full security system — no encoding/escaping, rate limiting, or
  exhaustive injection database, just the core pattern of not trusting
  extracted text.

## Output

`output/sample-output.json` — masked emails with classification, masked
credit cards with Luhn validity, phone numbers, URLs with a suspicious
flag, hashtags, and the excluded hostile lines.
