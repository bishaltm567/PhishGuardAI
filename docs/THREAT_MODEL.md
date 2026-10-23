# Threat model and limitations

## Assets and trust boundaries

- Analysts' submitted URLs, messages, uploaded EML files, case notes, and local case database.
- User input is untrusted and stays within the local application process.
- The optional local ML artifact is trusted only if obtained and reviewed from a controlled training workflow.
- There is no external intelligence provider or network fetch in the analyzer.

## Main controls

- No requests, DNS lookups, redirect following, attachment execution, HTML message rendering, or remote resource loading.
- URL, email, request, file, and MIME-part size limits.
- Standard-library EML parsing; only plain-text parts are analyzed; attachments are metadata only.
- Jinja autoescaping, HTML export escaping, CSV formula prefixing, CSRF protection, ORM queries, rate limits, and baseline security headers.
- Original user content is not stored or logged by application code.

## Risks and known gaps

- This starter has no authentication or analyst authorization. Keep it on a trusted local machine; do not deploy to a shared or public network.
- The development secret key must be replaced. Configure HTTPS and `COOKIE_SECURE=true` in a TLS-terminated deployment.
- In-memory rate limiting is process-local. Configure a shared backend before multi-worker hosting.
- Heuristics and model outputs are triage signals, can be wrong, and are not proof of malicious intent.
- Supplied `Authentication-Results` headers can be forged; no DNS or cryptographic verification is performed.
- IDN/punycode detection is a warning only and does not establish a homograph attack.
- Retention policy for local case records and database backups is an operator responsibility; delete the database when no longer needed.
- Joblib model files are Python serialization artifacts. Load only models created and reviewed in a trusted environment.

## Safe operational use

Use synthetic examples, verify high-risk requests through an independent channel, do not click suspicious links, and follow organizational incident-response procedures. This application does not block domains, modify mailboxes, or submit indicators to external services.
