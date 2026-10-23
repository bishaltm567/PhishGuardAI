# Testing

Install the development dependencies and run:

```powershell
python -m pip install -r requirements-dev.txt
python -m pytest
```

Tests use synthetic data and an in-memory SQLite database. They require no paid keys or live URLs. Coverage includes URL parsing and size guards, IDN/punycode handling, email language indicators, authentication-result absence/conflicts, EML attachment metadata, database persistence without raw input, CSRF, HTML escaping, CSV formula protection, scoring, and deterministic ML training on a synthetic-only fixture.

The ML pipeline has a separate command-line evaluation flow. Only claim reproducible metrics after running `ml/train.py` against a documented, legally usable dataset and retaining its generated metadata and evaluation output. Dataset-specific metrics are not real-world performance estimates.
