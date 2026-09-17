import os, datetime as dt, secrets
from functools import wraps
from flask import Flask, render_template, request, jsonify, g
from sqlalchemy import create_engine, text
from werkzeug.security import generate_password_hash, check_password_hash

RAW = os.environ.get("DATABASE_URL", "").strip()
if RAW.startswith("postgres://"):
    RAW = RAW.replace("postgres://", "postgresql://", 1)
if not RAW:
    raise SystemExit("DATABASE_URL is not set.")

engine = create_engine(RAW, pool_pre_ping=True, pool_size=5, max_overflow=5, future=True)

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
  id            SERIAL PRIMARY KEY,
  email         TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  is_admin      BOOLEAN NOT NULL DEFAULT FALSE,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS sessions (
  token      TEXT PRIMARY KEY,
  user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at TIMESTAMPTZ NOT NULL
);
CREATE TABLE IF NOT EXISTS daily_results (
  id            SERIAL PRIMARY KEY,
  user_id       INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  day           DATE NOT NULL,
  start_balance NUMERIC(16,2) NOT NULL,
  end_balance   NUMERIC(16,2) NOT NULL,
  pnl           NUMERIC(16,2) NOT NULL,
  note          TEXT DEFAULT '',
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (user_id, day)
);
CREATE TABLE IF NOT EXISTS requests (
  id         SERIAL PRIMARY KEY,
  user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  kind       TEXT NOT NULL,
  amount     NUMERIC(16,2) NOT NULL,
  address    TEXT DEFAULT '',
  status     TEXT NOT NULL DEFAULT 'pending',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  decided_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_requests_status ON requests(status);
CREATE INDEX IF NOT EXISTS idx_daily_user_day ON daily_results(user_id, day DESC);
"""

def rows(sql, params=None):
    with engine.connect() as c:
        return [dict(r) for r in c.execute(text(sql), params or {}).mappings().all()]

def one(sql, params=None):
    r = rows(sql, params)
    return r[0] if r else None

def run(sql, params=None):
    with engine.begin() as c:
        c.execute(text(sql), params or {})

def run_return(sql, params=None):
    with engine.begin() as c:
        return c.execute(text(sql), params or {}).mappings().first()

def migrate_if_needed():
    """Auto-migrate from the old single-portfolio schema to per-user."""
    with engine.begin() as c:
        has_table = c.execute(text("""
            SELECT 1 FROM information_schema.tables
            WHERE table_schema='public' AND table_name='daily_results'
        """)).first()
        if has_table:
            has_user_id = c.execute(text("""
                SELECT 1 FROM information_schema.columns
                WHERE table_name='daily_results' AND column_name='user_id'
            """)).first()
            if not has_user_id:
                print("[migrate] converting daily_results to per-user schema")
                c.execute(text("DROP TABLE daily_results CASCADE"))
        c.execute(text("DROP TABLE IF EXISTS settings CASCADE"))
        for stmt in SCHEMA.split(";"):
            s = stmt.strip()
            if s:
                c.execute(text(s))

def user_summary(user_id):
    hist = rows("""SELECT id, day::text AS day, start_balance::float AS start_balance,
                          end_balance::float AS end_balance, pnl::float AS pnl, note
                   FROM daily_results WHERE user_id = :u
                   ORDER BY day DESC LIMIT 365""", {"u": user_id})
    agg = one("""SELECT COALESCE(SUM(pnl),0)::float AS total,
                        COUNT(*) AS n,
                        COUNT(*) FILTER (WHERE pnl > 0) AS wins
                 FROM daily_results WHERE user_id = :u""", {"u": user_id})
    last = one("""SELECT end_balance::float AS b FROM daily_results
                  WHERE user_id = :u ORDER BY day DESC LIMIT 1""", {"u": user_id})
    flows = one("""SELECT
        COALESCE(SUM(CASE WHEN kind='deposit' AND status='approved' THEN amount END),0)::float AS deposited,
        COALESCE(SUM(CASE WHEN kind='withdraw' AND status='approved' THEN amount END),0)::float AS withdrawn
        FROM requests WHERE user_id = :u""", {"u": user_id})
    return {
        "balance": last["b"] if last else 0.0,
        "total_pnl": agg["total"],
        "days": agg["n"],
        "wins": agg["wins"],
        "deposited": flows["deposited"],
        "withdrawn": flows["withdrawn"],
        "history": hist,
    }

def init_admin():
    email = (os.environ.get("ADMIN_EMAIL") or "").strip().lower()
    pw = os.environ.get("ADMIN_PASSWORD") or ""
    if not email or not pw:
        return
    existing = one("SELECT id FROM users WHERE email = :e", {"e": email})
    if not existing:
        run("INSERT INTO users (email, password_hash, is_admin) VALUES (:e, :p, TRUE)",
            {"e": email, "p": generate_password_hash(pw)})
        print(f"[init] admin account created: {email}")
    else:
        run("UPDATE users SET is_admin = TRUE WHERE email = :e", {"e": email})

app = Flask(__name__)
app.config["JSON_SORT_KEYS"] = False
SESSION_DAYS = 30

def make_session(user_id):
    tok = secrets.token_urlsafe(32)
    run("INSERT INTO sessions (token, user_id, expires_at) VALUES (:t, :u, :x)",
        {"t": tok, "u": user_id,
         "x": dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=SESSION_DAYS)})
    return tok

def current_user():
    t = (request.headers.get("X-Token") or "").strip()
    if not t:
        return None
    row = one("""SELECT u.id, u.email, u.is_admin, s.expires_at
                 FROM sessions s JOIN users u ON u.id = s.user_id
                 WHERE s.token = :t""", {"t": t})
    if not row:
        return None
    if row["expires_at"] < dt.datetime.now(dt.timezone.utc):
        run("DELETE FROM sessions WHERE token = :t", {"t": t})
        return None
    return row

def require_user(f):
    @wraps(f)
    def w(*a, **k):
        u = current_user()
        if not u:
            return jsonify({"error": "Please sign in."}), 401
        g.user = u
        return f(*a, **k)
    return w

def require_admin(f):
    @wraps(f)
    def w(*a, **k):
        u = current_user()
        if not u or not u["is_admin"]:
            return jsonify({"error": "Unauthorized."}), 401
        g.user = u
        return f(*a, **k)
    return w

@app.get("/")
def home():
    return render_template("index.html")

# ---------- auth ----------
@app.post("/api/signup")
def signup():
    b = request.get_json(silent=True) or {}
    email = (b.get("email") or "").strip().lower()
    pw = b.get("password") or ""
    if "@" not in email or "." not in email.split("@")[-1] or len(email) < 6:
        return jsonify({"error": "Enter a valid email address."}), 400
    if len(pw) < 8:
        return jsonify({"error": "Password must be at least 8 characters."}), 400
    if one("SELECT id FROM users WHERE email = :e", {"e": email}):
        return jsonify({"error": "That email is already registered."}), 409
    row = run_return(
        "INSERT INTO users (email, password_hash) VALUES (:e, :p) RETURNING id, is_admin",
        {"e": email, "p": generate_password_hash(pw)})
    return jsonify({"token": make_session(row["id"]), "email": email,
                    "is_admin": row["is_admin"]}), 201

@app.post("/api/login")
def login():
    b = request.get_json(silent=True) or {}
    email = (b.get("email") or "").strip().lower()
    pw = b.get("password") or ""
    u = one("SELECT id, email, password_hash, is_admin FROM users WHERE email = :e", {"e": email})
    if not u or not check_password_hash(u["password_hash"], pw):
        return jsonify({"error": "Wrong email or password."}), 401
    return jsonify({"token": make_session(u["id"]), "email": u["email"], "is_admin": u["is_admin"]})

@app.post("/api/logout")
def logout():
    t = (request.headers.get("X-Token") or "").strip()
    if t:
        run("DELETE FROM sessions WHERE token = :t", {"t": t})
    return jsonify({"ok": True})

@app.get("/api/me")
@require_user
def me():
    reqs = rows("""SELECT id, kind, amount::float AS amount, address, status,
                          created_at::text AS created_at
                   FROM requests WHERE user_id = :u ORDER BY id DESC LIMIT 50""",
                {"u": g.user["id"]})
    return jsonify({"email": g.user["email"], "is_admin": g.user["is_admin"], "requests": reqs})

# ---------- user data ----------
@app.get("/api/summary")
@require_user
def summary():
    return jsonify(user_summary(g.user["id"]))

@app.post("/api/request")
@require_user
def create_request():
    b = request.get_json(silent=True) or {}
    kind = b.get("kind")
    address = (b.get("address") or "").strip()
    try:
        amount = round(float(b.get("amount")), 2)
    except (TypeError, ValueError):
        return jsonify({"error": "Enter a valid amount."}), 400
    if kind not in ("deposit", "withdraw"):
        return jsonify({"error": "Invalid request type."}), 400
    if amount < 10:
        return jsonify({"error": "Minimum amount is $10."}), 400
    if kind == "withdraw" and not address:
        return jsonify({"error": "A wallet address is required for withdrawals."}), 400
    if one("SELECT id FROM requests WHERE user_id = :u AND status = 'pending'", {"u": g.user["id"]}):
        return jsonify({"error": "You already have a pending request."}), 409
    row = run_return("""INSERT INTO requests (user_id, kind, amount, address)
                        VALUES (:u, :k, :a, :w) RETURNING id""",
                     {"u": g.user["id"], "k": kind, "a": amount, "w": address})
    return jsonify({"id": row["id"]}), 201

# ---------- admin ----------
@app.get("/api/admin/users")
@require_admin
def admin_users():
    return jsonify({"users": rows("""
        SELECT u.id, u.email, u.is_admin,
               COALESCE((SELECT end_balance FROM daily_results
                         WHERE user_id = u.id ORDER BY day DESC LIMIT 1), 0)::float AS balance,
               COALESCE((SELECT COUNT(*) FROM daily_results WHERE user_id = u.id), 0) AS days
        FROM users u ORDER BY u.id""")})

@app.get("/api/admin/user/<int:uid>/summary")
@require_admin
def admin_user_summary(uid):
    u = one("SELECT id, email FROM users WHERE id = :i", {"i": uid})
    if not u:
        return jsonify({"error": "User not found."}), 404
    return jsonify({"user": u, "summary": user_summary(uid)})

@app.post("/api/admin/trade")
@require_admin
def admin_trade():
    b = request.get_json(silent=True) or {}
    try:
        uid = int(b.get("user_id"))
    except (TypeError, ValueError):
        return jsonify({"error": "Pick a user first."}), 400
    if not one("SELECT id FROM users WHERE id = :i", {"i": uid}):
        return jsonify({"error": "User not found."}), 404
    day = (b.get("day") or "").strip() or dt.date.today().isoformat()
    note = (b.get("note") or "").strip()[:200]
    try:
        end_bal = round(float(b.get("balance")), 2)
        pnl = round(float(b.get("pnl")), 2)
    except (TypeError, ValueError):
        return jsonify({"error": "Balance and P/L must be numbers."}), 400

    prev = one("""SELECT end_balance::float AS b FROM daily_results
                  WHERE user_id = :u AND day < :d ORDER BY day DESC LIMIT 1""",
               {"u": uid, "d": day})
    existing = one("SELECT start_balance::float AS b FROM daily_results WHERE user_id = :u AND day = :d",
                   {"u": uid, "d": day})
    start = existing["b"] if existing else (prev["b"] if prev else 0.0)

    run("""INSERT INTO daily_results (user_id, day, start_balance, end_balance, pnl, note)
           VALUES (:u, :d, :s, :e, :p, :n)
           ON CONFLICT (user_id, day) DO UPDATE
           SET start_balance = :s, end_balance = :e, pnl = :p, note = :n""",
        {"u": uid, "d": day, "s": start, "e": end_bal, "p": pnl, "n": note})
    return jsonify({"ok": True})

@app.delete("/api/admin/trade/<int:uid>/<day>")
@require_admin
def admin_delete_trade(uid, day):
    run("DELETE FROM daily_results WHERE user_id = :u AND day = :d", {"u": uid, "d": day})
    return jsonify({"ok": True})

@app.get("/api/admin/requests")
@require_admin
def admin_requests():
    pending = rows("""SELECT r.id, r.kind, r.amount::float AS amount, r.address,
                             r.status, r.created_at::text AS created_at, u.email, u.id AS user_id
                      FROM requests r JOIN users u ON u.id = r.user_id
                      WHERE r.status = 'pending' ORDER BY r.id""")
    recent = rows("""SELECT r.id, r.kind, r.amount::float AS amount, r.status,
                            r.created_at::text AS created_at, u.email, u.id AS user_id
                     FROM requests r JOIN users u ON u.id = r.user_id
                     WHERE r.status <> 'pending'
                     ORDER BY r.decided_at DESC NULLS LAST LIMIT 25""")
    return jsonify({"pending": pending, "recent": recent})

@app.post("/api/admin/decide")
@require_admin
def admin_decide():
    b = request.get_json(silent=True) or {}
    status = b.get("status")
    if status not in ("approved", "rejected"):
        return jsonify({"error": "Invalid status."}), 400
    run("""UPDATE requests SET status = :s, decided_at = NOW()
           WHERE id = :i AND status = 'pending'""",
        {"s": status, "i": b.get("id")})
    return jsonify({"ok": True})

try:
    migrate_if_needed()
    init_admin()
except Exception as e:
    print("[init] error:", e)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=False)
