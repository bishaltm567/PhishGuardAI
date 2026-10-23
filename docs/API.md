# HTTP routes

This starter primarily exposes server-rendered HTML forms. State-changing form requests use Flask-WTF CSRF tokens.

| Method | Path | Purpose |
|---|---|---|
| GET | `/` | Dashboard counts from SQLite |
| GET, POST | `/analyze/url` | Analyze one HTTP(S) URL without network access |
| GET, POST | `/analyze/email` | Analyze plain-text content and optional supplied auth header |
| GET, POST | `/analyze/eml` | Parse bounded EML upload safely |
| GET | `/cases` | List recent cases; optional `?status=` filter |
| GET, POST | `/cases/<uuid>` | View/update case status and analyst notes |
| POST | `/cases/<uuid>/feedback` | Record analyst feedback separately from model training |
| GET | `/history` | Redirect to cases |
| GET | `/reports` | Export options |
| GET | `/reports/<uuid>.json` | Single-case JSON export |
| GET | `/reports/<uuid>.html` | Escaped single-case HTML export |
| GET | `/reports/cases.csv` | Case metadata CSV export |
| GET | `/analytics` | Database-backed distributions |
| GET | `/settings` | Provider/model/privacy status |
| GET | `/health` | Basic health status; no secrets |

Invalid form inputs produce an inline message. Oversized requests return HTTP 413; rate-limited requests return HTTP 429. No endpoint automatically opens or submits an indicator to an external service.
