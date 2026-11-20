import os, time, sqlite3, secrets, hashlib, logging, threading, asyncio, json
from contextlib import contextmanager
from datetime import datetime, timedelta
from functools import wraps
from concurrent.futures import ThreadPoolExecutor

import jwt as pyjwt
from flask import Flask, request, jsonify, g, send_from_directory
from flask_cors import CORS

import ff_client
import MultiScript

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("ff")

# ═════════════════════════ CONFIG ═════════════════════════
DB_PATH              = os.environ.get("DB_PATH", "ff_accounts.db")
SECRET_KEY           = os.environ.get("SECRET_KEY", secrets.token_hex(32))
JWT_ALGO             = "HS256"
USER_TOKEN_TTL_DAYS  = 365  # User stays logged in for 1 year

# NEW INSPECTOR CREDENTIALS
INSPECTOR_UID        = "8061230984"
INSPECTOR_PASSWORD   = "Saiful8061"

JWT_REFRESH_INTERVAL = int(os.environ.get("JWT_REFRESH_INTERVAL", 7 * 3600))
CHECK_COOLDOWN       = int(os.environ.get("CHECK_COOLDOWN", 30))

# ═════════════════════════ DATABASE ═══════════════════════
@contextmanager
def db():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

def init_db():
    with db() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, created_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS game_accounts (
            id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, uid TEXT NOT NULL, password TEXT NOT NULL,
            account_id TEXT, name TEXT, region TEXT, level INTEGER, exp INTEGER, last_exp INTEGER, last_level INTEGER,
            total_exp INTEGER DEFAULT 0, last_checked INTEGER, matches_played INTEGER DEFAULT 0, 
            match_status TEXT DEFAULT 'idle', created_at INTEGER NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE, UNIQUE(user_id, uid)
        );
        CREATE TABLE IF NOT EXISTS checks (
            id INTEGER PRIMARY KEY AUTOINCREMENT, account_id INTEGER NOT NULL, level INTEGER NOT NULL, exp INTEGER NOT NULL,
            exp_gained INTEGER, level_change INTEGER NOT NULL, checked_at INTEGER NOT NULL,
            FOREIGN KEY (account_id) REFERENCES game_accounts(id) ON DELETE CASCADE
        );
        """)
    log.info(f"DB ready at {DB_PATH}")

init_db()

# ═════════════════════════ INSPECTOR JWT ══════════════════
_inspector_lock  = threading.Lock()
_inspector_state = {"jwt": None, "account_id": None, "fetched_at": 0}

def _refresh_inspector_jwt(force: bool = False) -> str:
    with _inspector_lock:
        now = int(time.time())
        have = bool(_inspector_state["jwt"])
        age  = now - _inspector_state["fetched_at"]
        if have and not force and age < JWT_REFRESH_INTERVAL: return _inspector_state["jwt"]
        if have and force and age < 30: return _inspector_state["jwt"]
        
        log.info("Refreshing inspector JWT…")
        data = ff_client.login_account(INSPECTOR_UID, INSPECTOR_PASSWORD)
        _inspector_state["jwt"] = data["jwt"]
        _inspector_state["account_id"] = data["account_id"]
        _inspector_state["fetched_at"] = now
        return data["jwt"]

def force_refresh_inspector() -> str:
    return _refresh_inspector_jwt(force=True)

def fetch_player_via_inspector(target_uid: int) -> dict:
    try:
        return ff_client.fetch_player(_refresh_inspector_jwt(False), target_uid)
    except Exception:
        return ff_client.fetch_player(force_refresh_inspector(), target_uid)

def _inspector_bg_loop():
    time.sleep(2)
    while True:
        try: _refresh_inspector_jwt(force=True)
        except Exception as e: log.error(f"BG inspector refresh failed: {e}")
        time.sleep(JWT_REFRESH_INTERVAL)

# ═════════════════════════ AUTO STATS UPDATER ══════════════════
def _stats_auto_check_loop():
    while True:
        time.sleep(60)
        try:
            with db() as c:
                rows = c.execute("SELECT * FROM game_accounts WHERE match_status='playing'").fetchall()
            for row in rows:
                try: 
                    check_account(row, force=True)
                    with db() as c:
                        c.execute("UPDATE game_accounts SET matches_played = matches_played + 3 WHERE id=?", (row["id"],))
                except Exception as e: 
                    log.error(f"Auto check failed for {row['uid']}: {e}")
        except Exception: pass

# ═════════════════════════ MATCH MANAGER ══════════════════
class MatchManager:
    def __init__(self):
        self.workers = {}
        self.lock = threading.Lock()

    def start(self, account_id, uid, password):
        with self.lock:
            if account_id in self.workers: return False, "Already running"
            stop_event = threading.Event()
            thread = threading.Thread(target=self._run, args=(account_id, uid, password, stop_event), daemon=True)
            self.workers[account_id] = {"thread": thread, "stop": stop_event}
            thread.start()
            return True, "Started"

    def stop(self, account_id):
        with self.lock:
            if account_id in self.workers:
                self.workers[account_id]["stop"].set()
                return True
        return False

    def _run(self, account_id, uid, password, stop_event):
        with db() as c: c.execute("UPDATE game_accounts SET match_status='playing' WHERE id=?", (account_id,))
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        async def run_cycle():
            while not stop_event.is_set():
                try:
                    match_task = asyncio.create_task(MultiScript.amain(uid, password, max_parallel=3))
                    stop_waiter = asyncio.create_task(asyncio.to_thread(stop_event.wait))
                    done, pending = await asyncio.wait([match_task, stop_waiter], return_when=asyncio.FIRST_COMPLETED)
                    
                    if stop_waiter in done:
                        match_task.cancel()
                        try: await match_task
                        except asyncio.CancelledError: pass
                        break
                    else:
                        if match_task.exception():
                            log.error(f"Match Task Crashed for {uid}: {match_task.exception()}")
                        await asyncio.sleep(5)
                except Exception as e:
                    log.error(f"Match Cycle Error for {uid}: {e}")
                    await asyncio.sleep(5)

        try: loop.run_until_complete(run_cycle())
        finally:
            with db() as c: c.execute("UPDATE game_accounts SET match_status='idle' WHERE id=?", (account_id,))
            with self.lock:
                if account_id in self.workers: del self.workers[account_id]

match_manager = MatchManager()

# ═════════════════════════ USER AUTH ══════════════════════
def hash_pw(pw: str) -> str:
    salt = secrets.token_bytes(16)
    h = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, 200_000)
    return f"{salt.hex()}${h.hex()}"

def check_pw(pw: str, stored: str) -> bool:
    try:
        s_hex, h_hex = stored.split("$")
        return secrets.compare_digest(hashlib.pbkdf2_hmac("sha256", pw.encode(), bytes.fromhex(s_hex), 200_000), bytes.fromhex(h_hex))
    except Exception: return False

def make_user_token(uid: int) -> str:
    return pyjwt.encode({"sub": str(uid), "exp": datetime.utcnow() + timedelta(days=USER_TOKEN_TTL_DAYS)}, SECRET_KEY, algorithm=JWT_ALGO)

def require_auth(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "): return jsonify(error="Missing token"), 401
        try: g.user_id = int(pyjwt.decode(auth[7:].strip(), SECRET_KEY, algorithms=[JWT_ALGO])["sub"])
        except Exception: return jsonify(error="Invalid token"), 401
        return f(*args, **kwargs)
    return wrapper

# ═════════════════════ SERIALIZATION ══════════════════════
def _serialize(row) -> dict:
    level, exp           = row["level"], row["exp"]
    prev_level, prev_exp = row["last_level"], row["last_exp"]

    if level is None or prev_level is None: level_change = 0
    else: level_change = 1 if level > prev_level else -1 if level < prev_level else 0

    exp_gained = None
    if level_change == 0 and exp is not None and prev_exp is not None: 
        exp_gained = exp - prev_exp
    elif level_change > 0:
        exp_gained = exp # Level up resets exp, so current exp is what we gained post-levelup

    return {
        "id": row["id"], "uid": row["uid"], "name": row["name"], "region": row["region"],
        "level": level, "exp": exp, "prev_level": prev_level, "prev_exp": prev_exp,
        "exp_gained": exp_gained, "level_change": level_change, "last_checked": row["last_checked"],
        "matches_played": row["matches_played"], "match_status": row["match_status"],
        "total_exp": row["total_exp"], "has_password": bool(row["password"]) 
    }

def check_account(account_row, force: bool = False) -> dict:
    now = int(time.time())
    if (not force and account_row["last_checked"] and (now - account_row["last_checked"]) < CHECK_COOLDOWN):
        return _serialize(account_row)

    player = fetch_player_via_inspector(int(account_row["account_id"]))
    prev_level = account_row["level"] if account_row["level"] is not None else player["level"]
    prev_exp   = account_row["exp"]   if account_row["exp"]   is not None else player["exp"]

    level_change = (1 if player["level"] > prev_level else -1 if player["level"] < prev_level else 0)
    
    # Calculate exact exp gained (handling level up resets)
    if level_change == 0:
        exp_gained = max(0, player["exp"] - prev_exp)
    elif level_change > 0:
        exp_gained = player["exp"] # Gained current exp after reset
    else:
        exp_gained = 0 # Dropped level (unlikely)

    new_total_exp = (account_row["total_exp"] or 0) + exp_gained

    with db() as c:
        c.execute("""UPDATE game_accounts SET name=?, region=?, level=?, exp=?, last_exp=?, last_level=?, 
                     last_checked=?, total_exp=? WHERE id=?""",
            (player["name"], player["region"], player["level"], player["exp"], prev_exp, prev_level, 
             now, new_total_exp, account_row["id"]))
        c.execute("INSERT INTO checks (account_id, level, exp, exp_gained, level_change, checked_at) VALUES (?, ?, ?, ?, ?, ?)",
            (account_row["id"], player["level"], player["exp"], exp_gained, level_change, now))
        fresh = c.execute("SELECT * FROM game_accounts WHERE id=?", (account_row["id"],)).fetchone()
    return _serialize(fresh)

def _safe_check(row, force: bool) -> dict:
    try: return check_account(row, force=force)
    except Exception as e:
        item = _serialize(row); item["error"] = str(e); return item

# ═════════════════════════ FLASK APP ══════════════════════
app = Flask(__name__)
CORS(app)

@app.get("/")
def root(): 
    try: return send_from_directory(".", "index.html")
    except Exception: return jsonify(status="error", msg="index.html not found")

def _json(): return request.get_json(silent=True) or {}

@app.post("/api/register")
def api_register():
    b = _json()
    username, password = str(b.get("username", "")).strip(), str(b.get("password", ""))
    if not 3 <= len(username) <= 32 or not 6 <= len(password) <= 128: return jsonify(error="Invalid length"), 400
    with db() as c:
        if c.execute("SELECT 1 FROM users WHERE username=?", (username,)).fetchone(): return jsonify(error="Username exists"), 409
        cur = c.execute("INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)", (username, hash_pw(password), int(time.time())))
        uid = cur.lastrowid
    return jsonify(token=make_user_token(uid), user_id=uid, username=username)

@app.post("/api/login")
def api_login():
    b = _json()
    with db() as c: row = c.execute("SELECT * FROM users WHERE username=?", (str(b.get("username", "")).strip(),)).fetchone()
    if not row or not check_pw(str(b.get("password", "")), row["password_hash"]): return jsonify(error="Invalid credentials"), 401
    return jsonify(token=make_user_token(row["id"]), user_id=row["id"], username=row["username"])

@app.get("/api/me")
@require_auth
def api_me():
    with db() as c:
        row = c.execute("SELECT id, username, created_at FROM users WHERE id=?", (g.user_id,)).fetchone()
    if not row: return jsonify(error="User not found"), 404
    return jsonify(dict(row))

@app.post("/api/accounts")
@require_auth
def api_add_account():
    b = _json()
    uid, password = str(b.get("uid", "")).strip(), str(b.get("password", ""))
    if not uid or not password: return jsonify(error="UID and Password required"), 400
    with db() as c:
        if c.execute("SELECT 1 FROM game_accounts WHERE user_id=? AND uid=?", (g.user_id, uid)).fetchone(): return jsonify(error="Account already added"), 409
    try:
        login_data = ff_client.login_account(uid, password)
        target_acc_id = login_data["account_id"]
        player = fetch_player_via_inspector(target_acc_id)
    except Exception as e: return jsonify(error=f"Login failed: {e}"), 400

    now = int(time.time())
    with db() as c:
        cur = c.execute("""INSERT INTO game_accounts (user_id, uid, password, account_id, name, region, level, exp, last_exp, last_level, last_checked, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""", (g.user_id, uid, password, str(target_acc_id), player["name"], player["region"], player["level"], player["exp"], player["exp"], player["level"], now, now))
        c.execute("INSERT INTO checks (account_id, level, exp, exp_gained, level_change, checked_at) VALUES (?, ?, ?, ?, ?, ?)", (cur.lastrowid, player["level"], player["exp"], 0, 0, now))
        row = c.execute("SELECT * FROM game_accounts WHERE id=?", (cur.lastrowid,)).fetchone()
    return jsonify(_serialize(row))

@app.get("/api/accounts")
@require_auth
def api_list_accounts():
    with db() as c: rows = c.execute("SELECT * FROM game_accounts WHERE user_id=? ORDER BY id", (g.user_id,)).fetchall()
    return jsonify([_serialize(r) for r in rows])

@app.delete("/api/accounts/<int:account_id>")
@require_auth
def api_delete_account(account_id: int):
    match_manager.stop(account_id)
    with db() as c: c.execute("DELETE FROM game_accounts WHERE id=? AND user_id=?", (account_id, g.user_id))
    return jsonify(ok=True)

@app.post("/api/accounts/<int:account_id>/check")
@require_auth
def api_check_one(account_id: int):
    with db() as c: row = c.execute("SELECT * FROM game_accounts WHERE id=? AND user_id=?", (account_id, g.user_id)).fetchone()
    if not row: return jsonify(error="Not found"), 404
    try: return jsonify(check_account(row, force=True))
    except Exception as e: return jsonify(error=str(e)), 502

@app.post("/api/accounts/check-all")
@require_auth
def api_check_all():
    with db() as c: rows = c.execute("SELECT * FROM game_accounts WHERE user_id=?", (g.user_id,)).fetchall()
    if not rows: return jsonify([])
    with ThreadPoolExecutor(max_workers=2) as ex: results = list(ex.map(lambda r: _safe_check(r, True), rows))
    return jsonify(results)

@app.post("/api/accounts/<int:account_id>/match/start")
@require_auth
def api_start_match(account_id):
    with db() as c: row = c.execute("SELECT * FROM game_accounts WHERE id=? AND user_id=?", (account_id, g.user_id)).fetchone()
    if not row: return jsonify(error="Not found"), 404
    ok, msg = match_manager.start(row["id"], row["uid"], row["password"])
    if not ok: return jsonify(error=msg), 400
    return jsonify(ok=True, msg=msg)

@app.post("/api/accounts/<int:account_id>/match/stop")
@require_auth
def api_stop_match(account_id):
    match_manager.stop(account_id)
    return jsonify(ok=True)

@app.get("/api/inspector/status")
@require_auth
def api_inspector_status():
    age = (int(time.time()) - _inspector_state["fetched_at"] if _inspector_state["fetched_at"] else None)
    return jsonify(configured=True, has_jwt=bool(_inspector_state["jwt"]), jwt_age_secs=age, refresh_every=JWT_REFRESH_INTERVAL)

# ═════════════════════════ AUTO-LOAD ACCOUNTS.JSON ══════════════════════
def auto_load_accounts_json():
    """Reads accounts.json, extracts UID/pass, adds to DB, and auto-starts matches."""
    filepath = "accounts.json"
    if not os.path.exists(filepath): return
    
    log.info("Found accounts.json! Parsing...")
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        log.error(f"Failed to parse accounts.json: {e}")
        return

    extracted = []
    if isinstance(data, dict):
        # Format: {"uid": "password"}
        for k, v in data.items(): extracted.append((str(k), str(v)))
    elif isinstance(data, list):
        for item in data:
            if isinstance(item, dict):
                # Format: [{"uid": "...", "password": "..."}] or {"user": "...", "pass": "..."}
                uid = item.get("uid") or item.get("user") or item.get("username") or item.get("account") or item.get("id")
                pw = item.get("password") or item.get("pass") or item.get("token")
                if uid and pw: extracted.append((str(uid), str(pw)))
            elif isinstance(item, (list, tuple)) and len(item) >= 2:
                extracted.append((str(item[0]), str(item[1])))
            elif isinstance(item, str) and ":" in item:
                # Format: ["uid:password"]
                u, p = item.split(":", 1)
                extracted.append((u.strip(), p.strip()))

    if not extracted:
        log.warning("No valid UID/Password found in accounts.json")
        return

    # Create a dummy "admin" user to hold these accounts
    with db() as c:
        row = c.execute("SELECT id FROM users WHERE username='admin'").fetchone()
        if row: admin_id = row["id"]
        else:
            cur = c.execute("INSERT INTO users (username, password_hash, created_at) VALUES ('admin', ?, ?)", (hash_pw("admin123"), int(time.time()),))
            admin_id = cur.lastrowid

    for uid, pw in extracted:
        with db() as c:
            if c.execute("SELECT 1 FROM game_accounts WHERE user_id=? AND uid=?", (admin_id, uid)).fetchone():
                # Already exists, just auto-start it
                row = c.execute("SELECT * FROM game_accounts WHERE user_id=? AND uid=?", (admin_id, uid)).fetchone()
                match_manager.start(row["id"], uid, pw)
                continue
            
            try:
                login_data = ff_client.login_account(uid, pw)
                target_acc_id = login_data["account_id"]
                player = fetch_player_via_inspector(target_acc_id)
                now = int(time.time())
                
                cur = c.execute("""INSERT INTO game_accounts (user_id, uid, password, account_id, name, region, level, exp, last_exp, last_level, last_checked, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""", (admin_id, uid, pw, str(target_acc_id), player["name"], player["region"], player["level"], player["exp"], player["exp"], player["level"], now, now))
                c.execute("INSERT INTO checks (account_id, level, exp, exp_gained, level_change, checked_at) VALUES (?, ?, ?, ?, ?, ?)", (cur.lastrowid, player["level"], player["exp"], 0, 0, now))
                
                log.info(f"Auto-added {uid} from JSON. Starting match...")
                match_manager.start(cur.lastrowid, uid, pw)
            except Exception as e:
                log.error(f"Failed to auto-start {uid} from JSON: {e}")

if __name__ == "__main__":
    if INSPECTOR_UID and INSPECTOR_PASSWORD:
        threading.Thread(target=_inspector_bg_loop, daemon=True).start()
    threading.Thread(target=_stats_auto_check_loop, daemon=True).start()
    
    # Load JSON accounts on startup
    threading.Thread(target=auto_load_accounts_json, daemon=True).start()
    
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8000)), threaded=True, use_reloader=False)
