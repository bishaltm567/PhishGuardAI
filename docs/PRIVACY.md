# Privacy and data handling

URL and email analysis runs locally. URL analyzer never contacts the destination or resolves its host. Email parsing does not render HTML or open remote links. EML attachments are not executed or read beyond their metadata.

By default, case records retain timestamps, analysis type, risk score/category, rule findings, analyst status/notes, and a SHA-256 fingerprint of submitted content. Original URLs and message bodies are not saved. A hash of a predictable input can still be linkable, so the fingerprint should be treated as sensitive metadata. Avoid placing personal information in analyst notes.

The current build has no external intelligence provider; submitted content is not sent to a third party. The database lives under `instance/`. Operators should protect backups and delete the database and backups according to their retention needs. No regulatory compliance certification is claimed.
