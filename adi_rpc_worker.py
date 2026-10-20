# -*- coding: utf-8 -*-
"""
Persistent Lock-Free Native ADI & SQLite RPC Worker for Go Multi-Core Pool
==========================================================================
Each OS process spawned by `mac_studio_go` runs its own independent
Unicorn `ADIDWindowsEngine` instance in RAM (bypassing the Python GIL across
processes) and communicates with Go via ultra-fast JSON-Lines over stdin/stdout.
Also provides automatic permanent cloud backup/restore of `mac_auth_system.db`
to a Private Hugging Face Dataset (`mi2em2d/almino-vault`) when `HF_TOKEN` is set.
"""

import os
import sys
import json
import time
import uuid
import base64
import shutil
import sqlite3
import threading

# Redirect any accidental print() calls inside adi_win_engine to stderr
# so stdout remains 100% pure JSON-RPC lines for Go.
_real_stdout = sys.stdout
sys.stdout = sys.stderr

from adi_win_engine import get_adi_engine

HF_TOKEN = os.environ.get("HF_TOKEN", "").strip()
HF_VAULT_REPO = os.environ.get("HF_VAULT_REPO", "mi2em2d/almino-vault").strip()
_vault_restored = False
_vault_lock = threading.Lock()


def _merge_remote_into_local(db_path: str):
    if not HF_TOKEN:
        return
    try:
        from huggingface_hub import hf_hub_download
        remote_db = hf_hub_download(
            repo_id=HF_VAULT_REPO,
            filename="mac_auth_system.db",
            repo_type="dataset",
            token=HF_TOKEN,
            force_download=True,
        )
        if remote_db and os.path.exists(remote_db):
            tmp_rem = db_path + ".rem_tmp"
            shutil.copyfile(remote_db, tmp_rem)
            try:
                os.chmod(tmp_rem, 0o666)
            except Exception:
                pass
            if not os.path.exists(db_path):
                shutil.copyfile(tmp_rem, db_path)
                try:
                    os.chmod(db_path, 0o666)
                except Exception:
                    pass
            else:
                try:
                    os.chmod(db_path, 0o666)
                except Exception:
                    pass
                rconn = sqlite3.connect(tmp_rem, timeout=30)
                _ensure_db_schema(rconn)
                rconn.commit()
                rconn.close()

                conn = sqlite3.connect(db_path, timeout=30)
                _ensure_db_schema(conn)
                conn.execute("ATTACH DATABASE ? AS rem", (tmp_rem,))
                conn.execute("INSERT OR IGNORE INTO main.devices SELECT * FROM rem.devices")
                try:
                    conn.execute("INSERT OR IGNORE INTO main.users SELECT * FROM rem.users")
                except Exception:
                    pass
                conn.commit()
                conn.execute("DETACH DATABASE rem")
                conn.close()
            try:
                os.remove(tmp_rem)
            except Exception:
                pass
    except Exception as e:
        sys.stderr.write(f"[Vault Merge Notice] {e}\n")


def _cloud_restore_if_needed(db_path: str):
    global _vault_restored
    if _vault_restored or not HF_TOKEN:
        return
    _vault_restored = True
    _merge_remote_into_local(db_path)


def _cloud_backup_async(db_path: str):
    if not HF_TOKEN or not os.path.exists(db_path):
        return

    def _upload():
        with _vault_lock:
            try:
                _merge_remote_into_local(db_path)
                from huggingface_hub import HfApi
                api = HfApi(token=HF_TOKEN)
                api.create_repo(repo_id=HF_VAULT_REPO, repo_type="dataset", private=True, exist_ok=True)
                api.upload_file(
                    path_or_fileobj=db_path,
                    path_in_repo="mac_auth_system.db",
                    repo_id=HF_VAULT_REPO,
                    repo_type="dataset",
                    commit_message="Sync bound Mac devices",
                )
            except Exception as e:
                sys.stderr.write(f"[Vault Backup Warning] {e}\n")

    threading.Thread(target=_upload, daemon=True).start()


def _ensure_db_schema(conn: sqlite3.Connection):
    try:
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
    except Exception:
        pass
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE,
            password TEXT,
            phone TEXT,
            token_key TEXT UNIQUE,
            totp_secret TEXT,
            last_code TEXT,
            last_code_at REAL DEFAULT 0,
            adsid TEXT,
            udid TEXT,
            serial_number TEXT,
            server_model TEXT,
            spd_json TEXT,
            status TEXT DEFAULT 'ACTIVE',
            created_at TEXT,
            adi_pb_b64 TEXT,
            host_uuid TEXT,
            mid TEXT,
            routing_data TEXT,
            local_user_uuid TEXT,
            client_info TEXT,
            owner_user TEXT DEFAULT 'mina'
        )
        """
    )
    try:
        conn.execute("ALTER TABLE devices ADD COLUMN owner_user TEXT DEFAULT 'mina';")
    except Exception:
        pass
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password TEXT NOT NULL,
            role TEXT DEFAULT 'USER',
            credits INTEGER DEFAULT 0,
            created_at TEXT
        )
        """
    )
    default_admin_user = os.environ.get("ADMIN_USER", "mina").strip().lower()
    default_admin_pass = os.environ.get("ADMIN_PASS", "mina-vip").strip()
    conn.execute(
        """
        INSERT OR IGNORE INTO users (username, password, role, credits, created_at)
        VALUES (?, ?, 'ADMIN', 9999999, ?)
        """,
        (default_admin_user, default_admin_pass, time.strftime("%Y-%m-%d %H:%M:%S")),
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_devices_token ON devices(token_key);")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_devices_email ON devices(email);")
    conn.commit()


def _open_writable_db(db_path: str) -> sqlite3.Connection:
    if os.path.exists(db_path):
        try:
            os.chmod(db_path, 0o666)
        except Exception:
            pass
    conn = sqlite3.connect(db_path, timeout=30)
    conn.row_factory = sqlite3.Row
    _ensure_db_schema(conn)
    return conn


def _db_users_load(db_path: str) -> list:
    _cloud_restore_if_needed(db_path)
    conn = _open_writable_db(db_path)
    rows = conn.execute("SELECT * FROM users ORDER BY role ASC, username ASC").fetchall()
    result = [dict(r) for r in rows]
    conn.close()
    return result


def _db_user_upsert(db_path: str, u: dict) -> dict:
    conn = _open_writable_db(db_path)
    uname = (u.get("username") or "").strip().lower()
    upass = (u.get("password") or "").strip()
    role = (u.get("role") or "USER").strip().upper()
    credits = int(u.get("credits", 0))
    now_str = time.strftime("%Y-%m-%d %H:%M:%S")
    conn.execute(
        """
        INSERT INTO users (username, password, role, credits, created_at)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(username) DO UPDATE SET
            password = excluded.password,
            role = excluded.role,
            credits = excluded.credits
        """,
        (uname, upass, role, credits, now_str),
    )
    conn.commit()
    conn.close()
    _cloud_backup_async(db_path)
    return {"username": uname, "role": role, "credits": credits}


def _db_user_delete(db_path: str, username: str) -> dict:
    conn = _open_writable_db(db_path)
    uname = username.strip().lower()
    conn.execute("DELETE FROM users WHERE lower(username) = ? AND role != 'ADMIN'", (uname,))
    conn.commit()
    conn.close()
    _cloud_backup_async(db_path)
    return {"deleted": uname}


def _db_load_all(db_path: str) -> list:
    _cloud_restore_if_needed(db_path)
    if not os.path.exists(db_path):
        return []
    conn = _open_writable_db(db_path)
    rows = conn.execute("SELECT * FROM devices ORDER BY id DESC").fetchall()
    result = [dict(r) for r in rows]
    conn.close()
    return result


def _db_bind(db_path: str, p: dict) -> dict:
    conn = _open_writable_db(db_path)

    email = (p.get("email") or "").strip().lower()
    existing = conn.execute("SELECT id, token_key FROM devices WHERE lower(email) = ?", (email,)).fetchone()
    if existing and existing["token_key"]:
        token_key = existing["token_key"]
        dev_id = existing["id"]
        conn.execute(
            """
            UPDATE devices SET
                password = ?, phone = ?, adsid = ?, totp_secret = ?, spd_json = ?,
                adi_pb_b64 = ?, host_uuid = ?, udid = ?, mid = ?, routing_data = ?,
                local_user_uuid = ?, serial_number = ?, client_info = ?, status = 'ACTIVE'
            WHERE id = ?
            """,
            (
                p.get("password", ""),
                p.get("phone", ""),
                p.get("adsid", ""),
                p.get("totp_secret", ""),
                p.get("spd_json", ""),
                p.get("adi_pb_b64", ""),
                p.get("host_uuid", ""),
                p.get("udid", ""),
                p.get("mid", ""),
                p.get("routing_data", "17106176"),
                p.get("local_user_uuid", ""),
                p.get("serial_number", ""),
                p.get("client_info", ""),
                dev_id,
            ),
        )
    else:
        token_key = p.get("token_key") or f"AlMino_{uuid.uuid4().hex}"
        now_str = time.strftime("%Y-%m-%d %H:%M:%S")
        cur = conn.execute(
            """
            INSERT INTO devices (
                email, password, phone, token_key, totp_secret, adsid, udid,
                serial_number, server_model, spd_json, status, created_at,
                adi_pb_b64, host_uuid, mid, routing_data, local_user_uuid, client_info, owner_user
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'ACTIVE', ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                email,
                p.get("password", ""),
                p.get("phone", ""),
                token_key,
                p.get("totp_secret", ""),
                p.get("adsid", ""),
                p.get("udid", ""),
                p.get("serial_number", ""),
                p.get("server_model", "MacBookPro15,1"),
                p.get("spd_json", ""),
                now_str,
                p.get("adi_pb_b64", ""),
                p.get("host_uuid", ""),
                p.get("mid", ""),
                p.get("routing_data", "17106176"),
                p.get("local_user_uuid", ""),
                p.get("client_info", ""),
                p.get("owner_user") or "mina",
            ),
        )
        dev_id = cur.lastrowid

    conn.commit()
    conn.close()
    _cloud_backup_async(db_path)
    return {"id": dev_id, "token_key": token_key, "email": email}


def main():
    eng = get_adi_engine()
    _real_stdout.write(json.dumps({"ready": True}) + "\n")
    _real_stdout.flush()

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        req_id = None
        try:
            req = json.loads(line)
            req_id = req.get("id")
            cmd = req.get("cmd")

            if cmd == "ping":
                res = {"ok": True, "id": req_id, "data": "pong"}

            elif cmd == "provision":
                dev = eng.provision_new_virtual_mac()
                res = {"ok": True, "id": req_id, "data": dev}

            elif cmd == "anisette":
                ani = eng.get_anisette_headers(
                    pb_b64=req["pb_b64"],
                    host_uuid_hex=req["host_uuid"],
                    udid=req["udid"],
                    local_uuid=req["local_uuid"],
                    serial_number=req["serial_number"],
                    rinfo=str(req.get("rinfo") or "17106176"),
                )
                res = {"ok": True, "id": req_id, "data": ani}

            elif cmd == "sync":
                sim_bytes = base64.b64decode(req["sim_b64"])
                new_pb_b64 = eng.synchronize_machine(
                    pb_b64=req["pb_b64"],
                    host_uuid_hex=req["host_uuid"],
                    sim_bytes=sim_bytes,
                    udid=req["udid"],
                    local_uuid=req["local_uuid"],
                    serial_number=req["serial_number"],
                    rinfo=str(req.get("rinfo") or "17106176"),
                )
                ani = eng.get_anisette_headers(
                    pb_b64=new_pb_b64,
                    host_uuid_hex=req["host_uuid"],
                    udid=req["udid"],
                    local_uuid=req["local_uuid"],
                    serial_number=req["serial_number"],
                    rinfo=str(req.get("rinfo") or "17106176"),
                )
                res = {
                    "ok": True,
                    "id": req_id,
                    "data": {
                        "pb_b64": new_pb_b64,
                        "X-Apple-I-MD-M": ani["X-Apple-I-MD-M"],
                        "X-Apple-I-MD": ani["X-Apple-I-MD"],
                    },
                }

            elif cmd == "otp_code":
                ts = req.get("timestamp")
                out = eng.generate_otp_code(
                    pb_b64=req["pb_b64"],
                    host_uuid_hex=req["host_uuid"],
                    timestamp=ts,
                )
                res = {"ok": True, "id": req_id, "data": out}

            elif cmd == "db_load_all":
                rows = _db_load_all(req["db_path"])
                res = {"ok": True, "id": req_id, "data": rows}

            elif cmd == "db_bind":
                out = _db_bind(req["db_path"], req["payload"])
                res = {"ok": True, "id": req_id, "data": out}

            elif cmd == "db_users_load":
                rows = _db_users_load(req["db_path"])
                res = {"ok": True, "id": req_id, "data": rows}

            elif cmd == "db_user_upsert":
                out = _db_user_upsert(req["db_path"], req["user"])
                res = {"ok": True, "id": req_id, "data": out}

            elif cmd == "db_user_delete":
                out = _db_user_delete(req["db_path"], req["username"])
                res = {"ok": True, "id": req_id, "data": out}

            else:
                res = {"ok": False, "id": req_id, "error": f"Unknown cmd: {cmd}"}

        except Exception as e:
            res = {"ok": False, "id": req_id, "error": str(e)}

        _real_stdout.write(json.dumps(res, ensure_ascii=False) + "\n")
        _real_stdout.flush()


if __name__ == "__main__":
    main()
