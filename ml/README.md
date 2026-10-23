# Offline URL model

No dataset or trained artifact is bundled. Use a legally redistributable and documented CSV with `url,label` columns; labels may be `0/benign/legitimate` or `1/phishing/malicious`. Check dataset license, collection date, source, representation, and permitted purpose yourself. Record a citation/license reference with `--source`. This pipeline does not download datasets or contact external services.

Run from the project root:

```powershell
python -m pip install -r requirements.txt
python ml/train.py path\to\licensed_urls.csv --source "Dataset citation; license URL; collected YYYY-MM-DD"
```

The script removes invalid rows and duplicate URLs before a seeded stratified random split. This is not time-based evaluation, and near-duplicate URLs can still leak across the split. It writes a local joblib artifact and a metadata JSON file. Review the metrics and dataset limitations before any operational use. Do not present them as real-world threat rates.
