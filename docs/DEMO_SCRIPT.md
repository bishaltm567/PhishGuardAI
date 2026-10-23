# Safe demonstration scenarios

All samples below use reserved `.example`/`.test` domains or fabricated text. No real victim data or active malicious URL is needed.

| Scenario | Synthetic input | Expected behavior | Evidence / limitation |
|---|---|---|---|
| Benign URL | `https://www.example.com/about` | No structural warning (may show informational baseline) | Heuristics cannot establish safety |
| URL with multiple indicators | `http://192.0.2.10/secure-login?next=https%3A%2F%2Fexample.test` | IP host, HTTP, account wording, redirect-style parameter | All are heuristic warnings; reserved IP used |
| Benign business email | `The project review is scheduled for Thursday at 10:00.` | No configured language warning | Legitimate message can still be malicious in context |
| Synthetic credential lure | `Urgent: verify your password and send the verification code immediately.` | Urgency and credential-request findings | Text patterns can have false positives |
| Inconsistent auth header | `spf=pass; spf=fail; dkim=none` | SPF conflict; DKIM none; DMARC missing | User-supplied header is not independently verified |
| Provider unavailable/unchecked | Any analysis in default settings | Intelligence state is “not checked” | No provider is configured; this is not a clean verdict |

Reproduce by running the app, submitting each input at its matching analysis page, and inspecting the generated case. The test suite checks the core cases without contacting the network. Record actual observed results from your run; do not invent counts or model metrics.
