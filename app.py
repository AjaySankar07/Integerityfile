"""
File Integrity Monitoring (FIM) System
----------------------------------------
Workflow implemented:
 1. User uploads a file through the dashboard, giving their name.
 2. System computes SHA-256 of the file content.
 3. A record (username, filename, time, hash) is written to a tamper-evident
    ledger (SQLite table). Each ledger row is cryptographically chained to
    the previous row (like a mini blockchain) -- so if anyone edits a past
    row directly in the database, the chain breaks and the dashboard flags
    "LEDGER INTEGRITY: BROKEN".
 4. On every upload, the new hash is compared to the *last* stored hash for
    that filename:
        - no previous record  -> BASELINE (first known-good copy)
        - hash matches        -> MATCH (file unchanged)
        - hash differs        -> MISMATCH (file has been altered!)
 5. Dashboard shows live status per file + full audit trail per file +
    global ledger integrity check.

Run:
    pip install -r requirements.txt
    python app.py
Then open http://127.0.0.1:5000
"""

import hashlib
import os
import sqlite3
from datetime import datetime

from flask import Flask, render_template, request, redirect, url_for, flash, abort, send_file
from werkzeug.utils import secure_filename

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "instance", "fim_ledger.db")
EVIDENCE_DIR = os.path.join(BASE_DIR, "uploads", "evidence_store")
EVIDENCE_LOG = os.path.join(BASE_DIR, "instance", "evidence_log.txt")  # append-only mirror
GENESIS_HASH = "0" * 64  # anchor for the very first ledger entry

app = Flask(__name__)
app.secret_key = "dev-secret-key-change-me"  # fine for a student/demo project


@app.template_filter("evidence_exists")
def evidence_exists_filter(stored_path):
    """Jinja2 filter: returns True if the physical evidence file still exists."""
    if not stored_path:
        return False
    return os.path.isfile(stored_path)

os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
os.makedirs(EVIDENCE_DIR, exist_ok=True)


# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS records (
            id                INTEGER PRIMARY KEY AUTOINCREMENT,
            username          TEXT NOT NULL,
            filename          TEXT NOT NULL,
            upload_time       TEXT NOT NULL,
            file_hash         TEXT NOT NULL,
            status            TEXT NOT NULL,
            prev_file_hash    TEXT,
            stored_path       TEXT NOT NULL,
            prev_chain_hash   TEXT NOT NULL,
            record_hash       TEXT NOT NULL
        )
        """
    )
    conn.commit()
    conn.close()


def sha256_of_file(filestorage) -> str:
    """Compute SHA-256 of an uploaded file's bytes without corrupting the stream."""
    h = hashlib.sha256()
    filestorage.stream.seek(0)
    for chunk in iter(lambda: filestorage.stream.read(8192), b""):
        h.update(chunk)
    filestorage.stream.seek(0)
    return h.hexdigest()


def compute_record_hash(row_id, username, filename, upload_time, file_hash, status, prev_chain_hash):
    """Chain hash: binds this row's evidence to the *entire* ledger history so far."""
    payload = f"{row_id}|{username}|{filename}|{upload_time}|{file_hash}|{status}|{prev_chain_hash}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def get_last_global_record(conn):
    return conn.execute("SELECT * FROM records ORDER BY id DESC LIMIT 1").fetchone()


def get_last_record_for_file(conn, filename):
    return conn.execute(
        "SELECT * FROM records WHERE filename = ? ORDER BY id DESC LIMIT 1", (filename,)
    ).fetchone()


def append_evidence_log(row_id, username, filename, upload_time, file_hash, status, record_hash):
    """Human-readable, append-only mirror of the ledger -- the 'safety file'."""
    with open(EVIDENCE_LOG, "a", encoding="utf-8") as f:
        f.write(
            f"[{upload_time}] id={row_id} user={username} file={filename} "
            f"status={status} sha256={file_hash} chain={record_hash}\n"
        )


def verify_ledger_integrity(conn):
    """Recompute every chain hash in order and compare to what's stored.
    Returns (is_intact: bool, first_broken_row_id: int|None)."""
    rows = conn.execute("SELECT * FROM records ORDER BY id ASC").fetchall()
    prev_chain_hash = GENESIS_HASH
    for row in rows:
        expected = compute_record_hash(
            row["id"], row["username"], row["filename"], row["upload_time"],
            row["file_hash"], row["status"], row["prev_chain_hash"],
        )
        if row["prev_chain_hash"] != prev_chain_hash or row["record_hash"] != expected:
            return False, row["id"]
        prev_chain_hash = row["record_hash"]
    return True, None


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.route("/")
def dashboard():
    conn = get_db()
    latest_per_file = conn.execute(
        """
        SELECT r.* FROM records r
        INNER JOIN (
            SELECT filename, MAX(id) AS max_id FROM records GROUP BY filename
        ) latest ON r.filename = latest.filename AND r.id = latest.max_id
        ORDER BY r.upload_time DESC
        """
    ).fetchall()

    total_events = conn.execute("SELECT COUNT(*) AS c FROM records").fetchone()["c"]
    mismatch_count = conn.execute(
        "SELECT COUNT(*) AS c FROM records WHERE status = 'MISMATCH'"
    ).fetchone()["c"]

    intact, broken_row = verify_ledger_integrity(conn)
    conn.close()

    return render_template(
        "dashboard.html",
        files=latest_per_file,
        total_events=total_events,
        mismatch_count=mismatch_count,
        watched_count=len(latest_per_file),
        ledger_intact=intact,
        broken_row=broken_row,
    )


@app.route("/upload", methods=["GET", "POST"])
def upload():
    if request.method == "GET":
        return render_template("upload.html")

    username = (request.form.get("username") or "").strip()
    uploaded_file = request.files.get("file")

    if not username:
        flash("Please enter your name / user ID.", "error")
        return redirect(url_for("upload"))
    if not uploaded_file or uploaded_file.filename == "":
        flash("Please choose a file to upload.", "error")
        return redirect(url_for("upload"))

    filename = secure_filename(uploaded_file.filename)
    file_hash = sha256_of_file(uploaded_file)
    upload_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    conn = get_db()
    last_for_file = get_last_record_for_file(conn, filename)
    if last_for_file is None:
        status = "BASELINE"
        prev_file_hash = None
    elif last_for_file["file_hash"] == file_hash:
        status = "MATCH"
        prev_file_hash = last_for_file["file_hash"]
    else:
        status = "MISMATCH"
        prev_file_hash = last_for_file["file_hash"]

    # Save an immutable evidence copy of the exact bytes received
    last_global = get_last_global_record(conn)
    next_id = (last_global["id"] + 1) if last_global else 1
    stored_name = f"{next_id:06d}_{filename}"
    stored_path = os.path.join(EVIDENCE_DIR, stored_name)
    uploaded_file.stream.seek(0)
    uploaded_file.save(stored_path)

    prev_chain_hash = last_global["record_hash"] if last_global else GENESIS_HASH
    record_hash = compute_record_hash(
        next_id, username, filename, upload_time, file_hash, status, prev_chain_hash
    )

    conn.execute(
        """INSERT INTO records
           (id, username, filename, upload_time, file_hash, status,
            prev_file_hash, stored_path, prev_chain_hash, record_hash)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (next_id, username, filename, upload_time, file_hash, status,
         prev_file_hash, stored_path, prev_chain_hash, record_hash),
    )
    conn.commit()
    conn.close()

    append_evidence_log(next_id, username, filename, upload_time, file_hash, status, record_hash)

    flash(f'"{filename}" logged as {status}.', "success" if status != "MISMATCH" else "alert")
    return redirect(url_for("history", filename=filename))


@app.route("/history/<path:filename>")
def history(filename):
    conn = get_db()
    rows = conn.execute(
        "SELECT * FROM records WHERE filename = ? ORDER BY id ASC", (filename,)
    ).fetchall()
    conn.close()
    if not rows:
        abort(404)
    return render_template("history.html", filename=filename, rows=rows)


@app.route("/ledger")
def ledger():
    conn = get_db()
    rows = conn.execute("SELECT * FROM records ORDER BY id ASC").fetchall()
    intact, broken_row = verify_ledger_integrity(conn)
    conn.close()
    return render_template("ledger.html", rows=rows, ledger_intact=intact, broken_row=broken_row)


# ---------------------------------------------------------------------------
# Evidence Management routes
# ---------------------------------------------------------------------------
@app.route("/lookup")
def lookup():
    """Record ID lookup page — shows full record details + download/delete actions."""
    query_id = request.args.get("id", "").strip()
    record = None
    file_exists = False

    if query_id:
        try:
            rid = int(query_id)
        except ValueError:
            flash("Record ID must be a positive integer.", "error")
            return render_template("lookup.html", record=None, query_id=query_id, file_exists=False)

        conn = get_db()
        record = conn.execute("SELECT * FROM records WHERE id = ?", (rid,)).fetchone()
        conn.close()

        if record:
            file_exists = bool(record["stored_path"]) and os.path.isfile(record["stored_path"])

    return render_template(
        "lookup.html",
        record=record,
        query_id=query_id or None,
        file_exists=file_exists,
    )


@app.route("/evidence/<int:record_id>/download")
def download_evidence(record_id):
    """Serve the exact evidence file bytes for a given record ID."""
    conn = get_db()
    row = conn.execute("SELECT * FROM records WHERE id = ?", (record_id,)).fetchone()
    conn.close()

    if row is None:
        abort(404)

    stored_path = row["stored_path"]
    if not stored_path or not os.path.isfile(stored_path):
        flash(f"Evidence file for record #{record_id} has been removed and cannot be downloaded.", "error")
        return redirect(url_for("lookup", id=record_id))

    return send_file(
        stored_path,
        as_attachment=True,
        download_name=row["filename"],
    )


@app.route("/evidence/<int:record_id>/delete", methods=["POST"])
def delete_evidence(record_id):
    """Delete the physical evidence file only — the ledger row is never touched."""
    conn = get_db()
    row = conn.execute("SELECT * FROM records WHERE id = ?", (record_id,)).fetchone()
    conn.close()

    if row is None:
        abort(404)

    stored_path = row["stored_path"]
    if stored_path and os.path.isfile(stored_path):
        os.remove(stored_path)
        flash(
            f'Evidence file for record #{record_id} ("{row["filename"]}") has been removed. '
            f"The ledger entry and chain hash remain intact.",
            "success",
        )
    else:
        flash(f"Evidence file for record #{record_id} was already removed.", "error")

    # Redirect back to wherever the caller came from (history page or lookup page)
    redirect_to = request.form.get("redirect_to", "lookup")
    history_filename = request.form.get("history_filename", "")
    if redirect_to == "history" and history_filename:
        return redirect(url_for("history", filename=history_filename))
    return redirect(url_for("lookup", id=record_id))


if __name__ == "__main__":
    init_db()
    app.run(debug=True)
