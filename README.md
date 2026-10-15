# File Integrity Monitoring (FIM) — Chain-of-Custody Ledger

A Flask web app that detects unauthorized file changes by hashing every
upload and comparing it to the last known-good copy, with a tamper-evident
audit ledger so the *evidence itself* can't be silently edited either.

## How it matches your workflow

1. **Dashboard** — shows every watched file's current status at a glance.
2. **User uploads a file** (with their name) via the Upload page.
3. The app stores `username, filename, upload_time, SHA-256 hash` as a row
   in the ledger (SQLite), plus a byte-for-byte copy of the file in
   `uploads/evidence_store/` as physical evidence.
4. If the same filename is uploaded again, the app hashes it again and
   compares it to the **previous** hash for that filename:
   - No previous record → `BASELINE`
   - Hash matches → `MATCH` (unchanged)
   - Hash differs → `MISMATCH` (tampered!) — shown in red on the dashboard
5. **The ledger can't be quietly edited.** Every row's `record_hash` is a
   SHA-256 of that row's data *plus* the previous row's `record_hash` —
   exactly like a mini blockchain. If anyone opens the SQLite file directly
   and changes a username, filename, or hash, the chain no longer
   recomputes correctly from that point forward, and the dashboard shows
   **"LEDGER INTEGRITY: BROKEN"** with the exact record number where it broke.

## Run it

```bash
pip install -r requirements.txt
python app.py
```

Open **http://127.0.0.1:5000**

## Pages

| Route | Purpose |
|---|---|
| `/` | Dashboard — current status per file, ledger integrity banner, quick stats |
| `/upload` | Upload a file to log/re-verify it |
| `/history/<filename>` | Full version history of one file (chain of hashes) |
| `/ledger` | Global chain-of-custody ledger with visual chain of every event |

## Try the demo scenario

1. Upload `config.txt` as user `raj` → status **BASELINE**.
2. Upload the exact same file again → status **MATCH**.
3. Edit the file slightly and upload it again as `attacker` → status
   **MISMATCH**, flagged in red on the dashboard.
4. (Optional, to prove the ledger is tamper-evident) Open
   `instance/fim_ledger.db` with a SQLite browser and edit any row's
   `username` or `file_hash` directly, bypassing the app. Reload the
   dashboard — it will now say **LEDGER INTEGRITY: BROKEN** and name the
   exact record that no longer matches its chain hash.

## Project structure

```
fim_project/
├── app.py                     # Flask app, hashing, chain logic, routes
├── requirements.txt
├── templates/                 # Jinja2 HTML templates
├── static/style.css           # Case-file / evidence-ledger visual theme
├── instance/
│   ├── fim_ledger.db          # SQLite ledger (created on first run)
│   └── evidence_log.txt       # Append-only human-readable mirror log
└── uploads/evidence_store/    # Immutable copies of every uploaded file version
```

## Ideas to extend further

- Add login/roles so only authorized users can upload for certain filenames.
- Add a "restore" button that re-downloads the last `MATCH`/`BASELINE`
  version's evidence copy.
- Add email/desktop alerts on `MISMATCH`.
- Add a background `watchdog`-based folder monitor alongside manual uploads.
