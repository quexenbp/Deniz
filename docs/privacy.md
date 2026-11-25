# Privacy and retention

## Redaction

Reports and case exports accept `--redact`. It masks e-mail local parts and
phone numbers, including inside attributes, source URLs, findings and notes:

```bash
deniz report <run-id> --redact
deniz case export acme --redact --zip
```

API and MCP equivalents pass `{"redact": true}` / `"redact": true`. Masking is
format-independent and applies before rendering, so HTML, STIX, JSONL and PDF
all carry the masked values. Domain names, usernames and IPs are left intact.
Phone matching relies on libphonenumber and only recognises international
formats in free text; an observation typed as `phone` is always masked.

Redaction is one-way in the generated artifact. The stored run stays raw.

## Retention

Recommended defaults: runs 30–90 days, audit 180 days, archived cases 180 days.

```bash
deniz runs prune --prune-days 90
deniz case prune --days 180 --yes
deniz audit prune --days 180 --yes
```

`runs prune` keeps runs attached to cases unless `--include-case-runs` is
passed. `case prune` only deletes archived cases and cascades monitors and
findings. Deleting a case does not delete its run directories.

## Backups

`deniz backup` includes the audit log but not provider credentials. Encrypt
backup directories at rest if they leave the host.
