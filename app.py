import os, csv, io, sqlite3, hashlib, secrets, uuid
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, flash, Response, abort, send_from_directory
from werkzeug.utils import secure_filename

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "shiva_janseva.db")

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "CHANGE-ME-IN-PRODUCTION")
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "0") == "1",
)

MIN_TOPUP = 100.0
MIN_REQUIRED_BALANCE = 20.0
SERVICE_CHARGE = 100.0
ALLOWED_PDF_EXTENSIONS = {"pdf"}
UPLOAD_DIR = os.path.join(os.path.dirname(__file__), "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)
MAX_PDF_SIZE = 10 * 1024 * 1024

SERVICES = [
    "Aadhaar Name Update Assistance",
    "Aadhaar DOB Update Assistance",
    "Aadhaar Full Name Update Assistance",
    "Birth Certificate PDF Download Assistance",
    "Voter ID Download Assistance",
    "Voter Number Link Assistance",
    "PAN Card",
    "Income/Caste/Residence Certificate",
    "Online Form / Application",
    "Print / Scan / Photocopy",
    "Other",
]

def db():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    return con

def hash_password(password, salt=None):
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 260000)
    return f"pbkdf2_sha256$260000${salt}${digest.hex()}"

def verify_password(password, stored):
    try:
        _, rounds, salt, digest = stored.split("$", 3)
        check = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), int(rounds)).hex()
        return secrets.compare_digest(check, digest)
    except Exception:
        return False

def next_retailer_username(con):
    rows = con.execute("SELECT username FROM retailers WHERE username IS NOT NULL AND username LIKE 'RET%'").fetchall()
    used = set()
    for row in rows:
        value = (row["username"] or "").strip()
        if value.startswith("RET") and value[3:].isdigit():
            used.add(int(value[3:]))
    n = 1
    while n in used:
        n += 1
    return f"RET{n:04d}"

def ensure_column(con, table, column, definition):
    cols = {r["name"] for r in con.execute(f"PRAGMA table_info({table})").fetchall()}
    if column not in cols:
        con.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")


SERVICE_FIELDS = {
    "Aadhaar Name Update Assistance": [("customer_name","Customer Name","text",True),("mobile","Mobile Number","tel",True),("aadhaar_last4","Aadhaar Last 4 Digits","text",False),("new_name","New Name","text",True)],
    "Aadhaar DOB Update Assistance": [("customer_name","Customer Name","text",True),("mobile","Mobile Number","tel",True),("aadhaar_last4","Aadhaar Last 4 Digits","text",False),("new_dob","New Date of Birth","date",True)],
    "Aadhaar Full Name Update Assistance": [("customer_name","Customer Name","text",True),("mobile","Mobile Number","tel",True),("aadhaar_last4","Aadhaar Last 4 Digits","text",False),("new_name","Full New Name","text",True)],
    "Birth Certificate PDF Download Assistance": [("customer_name","Applicant / Child Name","text",True),("mobile","Mobile Number","tel",True),("registration_number","Registration Number","text",True),("state_name","State Name","text",True),("district_name","District Name","text",False)],
    "Voter ID Download Assistance": [("customer_name","Customer Name","text",True),("mobile","Mobile Number","tel",True),("voter_number","Voter Number / EPIC Number","text",True),("state_name","State Name","text",False)],
    "Voter Number Link Assistance": [("customer_name","Customer Name","text",True),("mobile","Mobile Number","tel",True),("voter_number","Voter Number / EPIC Number","text",True),("mobile_to_link","Mobile Number to Link","tel",True)],
    "PAN Card": [("customer_name","Customer Name","text",True),("mobile","Mobile Number","tel",True),("pan_number","PAN Number (if existing)","text",False),("application_type","Application Type","text",True)],
    "Income/Caste/Residence Certificate": [("customer_name","Customer Name","text",True),("mobile","Mobile Number","tel",True),("certificate_type","Certificate Type","text",True),("application_number","Application Number (if any)","text",False),("state_name","State Name","text",True),("district_name","District Name","text",False)],
    "Online Form / Application": [("customer_name","Applicant Name","text",True),("mobile","Mobile Number","tel",True),("application_name","Application / Form Name","text",True),("application_number","Application Number (if any)","text",False)],
    "Print / Scan / Photocopy": [("customer_name","Customer Name","text",True),("mobile","Mobile Number","tel",True),("copies","Number of Copies","number",False)],
    "Other": [("customer_name","Customer Name","text",True),("mobile","Mobile Number","tel",True),("service_details","Service Details","text",True)]
}

def init_db():
    con = db()
    con.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        must_change INTEGER NOT NULL DEFAULT 1
    );

    CREATE TABLE IF NOT EXISTS requests (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        phone TEXT NOT NULL,
        service TEXT NOT NULL,
        preferred_date TEXT,
        message TEXT,
        status TEXT NOT NULL DEFAULT 'Pending',
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS retailers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        phone TEXT NOT NULL,
        username TEXT UNIQUE,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS distributors (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        phone TEXT NOT NULL,
        username TEXT,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS wallet (
        id INTEGER PRIMARY KEY CHECK(id=1),
        balance REAL NOT NULL DEFAULT 1000000
    );

    CREATE TABLE IF NOT EXISTS wallet_transfers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        recipient_type TEXT NOT NULL,
        recipient_id INTEGER NOT NULL,
        amount REAL NOT NULL,
        note TEXT,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS wallet_topups (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        retailer_id INTEGER NOT NULL,
        amount REAL NOT NULL,
        transaction_id TEXT NOT NULL UNIQUE,
        status TEXT NOT NULL DEFAULT 'Pending',
        admin_note TEXT,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        processed_at TEXT
    );

    CREATE TABLE IF NOT EXISTS retailer_wallet_ledger (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        retailer_id INTEGER NOT NULL,
        amount REAL NOT NULL,
        balance_after REAL NOT NULL,
        type TEXT NOT NULL,
        reference_id INTEGER,
        note TEXT,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS service_charges (
        service TEXT PRIMARY KEY,
        charge REAL NOT NULL DEFAULT 100
    );

    CREATE TABLE IF NOT EXISTS retailer_requests (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        retailer_id INTEGER NOT NULL,
        name TEXT NOT NULL,
        phone TEXT NOT NULL,
        service TEXT NOT NULL,
        message TEXT,
        charge REAL NOT NULL DEFAULT 100,
        status TEXT NOT NULL DEFAULT 'Pending',
        pdf_filename TEXT,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS retailer_presence (
        retailer_id INTEGER PRIMARY KEY,
        service TEXT,
        last_seen TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        online INTEGER NOT NULL DEFAULT 0
    );
    """)

    # Migrate older retailer table safely.
    ensure_column(con, "retailers", "password_hash", "TEXT")
    ensure_column(con, "retailers", "wallet_balance", "REAL NOT NULL DEFAULT 0")
    ensure_column(con, "retailer_requests", "pdf_filename", "TEXT")

    if not con.execute("SELECT 1 FROM users WHERE username='admin'").fetchone():
        con.execute(
            "INSERT INTO users(username,password_hash,must_change) VALUES(?,?,1)",
            ("admin", hash_password("Shiva@2026!"))
        )

    if not con.execute("SELECT 1 FROM wallet WHERE id=1").fetchone():
        con.execute("INSERT INTO wallet(id,balance) VALUES(1,1000000)")

    for _service in SERVICES:
        con.execute("INSERT OR IGNORE INTO service_charges(service,charge) VALUES(?,?)", (_service, 100))

    con.commit()
    con.close()

init_db()

def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("admin_id"):
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapper

def retailer_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("retailer_id"):
            return redirect(url_for("retailer_login"))
        return fn(*args, **kwargs)
    return wrapper

@app.context_processor
def globals():
    return {
        "business_name": "Shiva Janseva Kendra",
        "location": "Roshnabad",
        "phone": "7505955205",
        "services": SERVICES,
        "min_topup": MIN_TOPUP,
        "min_required_balance": MIN_REQUIRED_BALANCE,
        "service_charge": SERVICE_CHARGE,
        "service_fields": SERVICE_FIELDS,
    }

@app.route("/")
def index():
    return render_template("index.html")

@app.post("/request")
def service_request():
    name = request.form.get("name", "").strip()
    phone = request.form.get("phone", "").strip()
    service = request.form.get("service", "").strip()
    date = request.form.get("preferred_date", "").strip()
    message = request.form.get("message", "").strip()

    if not name or not phone or service not in SERVICES:
        flash("Please fill the required fields correctly.", "error")
        return redirect(url_for("index"))

    digits = "".join(c for c in phone if c.isdigit())
    if len(digits) < 10 or len(digits) > 12:
        flash("Please enter a valid mobile number.", "error")
        return redirect(url_for("index"))

    con = db()
    con.execute(
        "INSERT INTO requests(name,phone,service,preferred_date,message) VALUES(?,?,?,?,?)",
        (name, phone, service, date, message)
    )
    # Backward-compatible migration for existing databases.
    cols = {row[1] for row in con.execute("PRAGMA table_info(retailer_requests)").fetchall()}
    if "pdf_filename" not in cols:
        con.execute("ALTER TABLE retailer_requests ADD COLUMN pdf_filename TEXT")
    con.commit()
    con.close()
    flash("Request submitted successfully. Kendra will contact you.", "success")
    return redirect(url_for("index"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        con = db()
        user = con.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        con.close()

        if user and verify_password(password, user["password_hash"]):
            session.clear()
            session["admin_id"] = user["id"]
            session["username"] = user["username"]
            session["must_change"] = bool(user["must_change"])
            if user["must_change"]:
                return redirect(url_for("change_password"))
            return redirect(url_for("admin"))

        flash("Invalid login details.", "error")
    return render_template("login.html")

@app.route("/retailer-login", methods=["GET", "POST"])
def retailer_login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        con = db()
        retailer = con.execute(
            "SELECT * FROM retailers WHERE username=?", (username,)
        ).fetchone()
        con.close()

        if retailer and retailer["password_hash"] and verify_password(password, retailer["password_hash"]):
            session.clear()
            session["retailer_id"] = retailer["id"]
            session["retailer_username"] = retailer["username"]
            return redirect(url_for("retailer_dashboard"))

        flash("Invalid retailer login details.", "error")
    return render_template("retailer_login.html")

@app.route("/retailer-recover", methods=["GET", "POST"])
def retailer_recover():
    username = None
    if request.method == "POST":
        phone = request.form.get("phone", "").strip()
        if not phone:
            flash("Registered mobile number enter karein.", "error")
        else:
            con = db()
            retailer = con.execute("SELECT username FROM retailers WHERE phone=?", (phone,)).fetchone()
            con.close()
            if retailer:
                username = retailer["username"]
                flash("User ID mil gaya. Password sirf Admin reset/change karega.", "success")
            else:
                flash("Is mobile number se koi retailer nahi mila.", "error")
    return render_template("retailer_recover.html", username=username)

@app.get("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))

@app.route("/change-password", methods=["GET", "POST"])
@admin_required
def change_password():
    if request.method == "POST":
        new = request.form.get("new_password", "")
        confirm = request.form.get("confirm_password", "")
        if len(new) < 10:
            flash("Password must be at least 10 characters.", "error")
        elif new != confirm:
            flash("Passwords do not match.", "error")
        else:
            con = db()
            con.execute(
                "UPDATE users SET password_hash=?, must_change=0 WHERE id=?",
                (hash_password(new), session["admin_id"])
            )
            con.commit()
            con.close()
            session["must_change"] = False
            flash("Password changed successfully.", "success")
            return redirect(url_for("admin"))
    return render_template("change.html")

@app.get("/admin")
@admin_required
def admin():
    if session.get("must_change"):
        return redirect(url_for("change_password"))

    q = request.args.get("q", "").strip()
    status = request.args.get("status", "").strip()

    con = db()
    where, args = [], []
    if q:
        where.append("(name LIKE ? OR phone LIKE ? OR service LIKE ?)")
        args += [f"%{q}%", f"%{q}%", f"%{q}%"]
    if status in ("Pending", "Contacted", "Completed", "Cancelled"):
        where.append("status=?")
        args.append(status)

    clause = (" WHERE " + " AND ".join(where)) if where else ""
    rows = con.execute(
        "SELECT * FROM requests" + clause + " ORDER BY id DESC", args
    ).fetchall()

    stats = {
        s: con.execute("SELECT COUNT(*) FROM requests WHERE status=?", (s,)).fetchone()[0]
        for s in ("Pending", "Contacted", "Completed", "Cancelled")
    }
    retailers = con.execute("SELECT * FROM retailers ORDER BY id DESC").fetchall()
    distributors = con.execute("SELECT * FROM distributors ORDER BY id DESC").fetchall()
    wallet = con.execute("SELECT balance FROM wallet WHERE id=1").fetchone()["balance"]
    transfers = con.execute("""
        SELECT wt.*,
        CASE WHEN wt.recipient_type='Retailer' THEN r.name ELSE d.name END AS recipient_name
        FROM wallet_transfers wt
        LEFT JOIN retailers r ON wt.recipient_type='Retailer' AND wt.recipient_id=r.id
        LEFT JOIN distributors d ON wt.recipient_type='Distributor' AND wt.recipient_id=d.id
        ORDER BY wt.id DESC LIMIT 20
    """).fetchall()
    retailer_requests = con.execute("""
        SELECT rr.*, r.name AS retailer_name, r.username AS retailer_username
        FROM retailer_requests rr
        JOIN retailers r ON r.id=rr.retailer_id
        ORDER BY rr.id DESC LIMIT 100
    """).fetchall()
    service_charges = con.execute("SELECT service,charge FROM service_charges ORDER BY service").fetchall()

    topups = con.execute("""
        SELECT wt.*, r.name AS retailer_name, r.username AS retailer_username
        FROM wallet_topups wt
        JOIN retailers r ON r.id=wt.retailer_id
        ORDER BY wt.id DESC LIMIT 50
    """).fetchall()
    retailer_presence = con.execute("""
        SELECT r.id, r.name, r.username, r.phone, p.service, p.last_seen,
               CASE WHEN p.retailer_id IS NOT NULL AND p.online=1
                         AND p.last_seen >= datetime('now','-30 seconds')
                    THEN 1 ELSE 0 END AS is_online
        FROM retailers r
        LEFT JOIN retailer_presence p ON p.retailer_id=r.id
        ORDER BY r.id
    """).fetchall()
    con.close()

    return render_template(
        "admin.html", rows=rows, stats=stats, q=q,
        selected_status=status, retailers=retailers,
        distributors=distributors, wallet=wallet,
        transfers=transfers, topups=topups, retailer_requests=retailer_requests, service_charges=service_charges,
        retailer_presence=retailer_presence
    )

@app.post("/admin/add-retailer")
@admin_required
def add_retailer():
    name = request.form.get("name", "").strip()
    phone = request.form.get("phone", "").strip()
    password = request.form.get("password", "")

    if not name or not phone or len(password) < 6:
        flash("Retailer name, mobile and password (6+ chars) are required. User ID automatically generate hoga.", "error")
        return redirect(url_for("admin"))

    con = db()
    username = next_retailer_username(con)
    try:
        con.execute(
            "INSERT INTO retailers(name,phone,username,password_hash,wallet_balance) VALUES(?,?,?,?,0)",
            (name, phone, username, hash_password(password))
        )
        con.commit()
        flash(f"Retailer added. Auto User ID: {username}", "success")
    except sqlite3.IntegrityError:
        con.rollback()
        flash("Retailer could not be added. Please try again.", "error")
    finally:
        con.close()
    return redirect(url_for("admin"))

@app.post("/admin/add-distributor")
@admin_required
def add_distributor():
    name = request.form.get("name", "").strip()
    phone = request.form.get("phone", "").strip()
    username = request.form.get("username", "").strip()
    if not name or not phone:
        flash("Distributor name and mobile are required.", "error")
    else:
        con = db()
        con.execute(
            "INSERT INTO distributors(name,phone,username) VALUES(?,?,?)",
            (name, phone, username or None)
        )
        con.commit()
        con.close()
        flash("Distributor added successfully.", "success")
    return redirect(url_for("admin"))

@app.post("/admin/transfer")
@admin_required
def transfer_balance():
    recipient_type = request.form.get("recipient_type", "")
    try:
        recipient_id = int(request.form.get("recipient_id", "0"))
        amount = float(request.form.get("amount", "0"))
    except ValueError:
        recipient_id, amount = 0, 0
    note = request.form.get("note", "").strip()

    if recipient_type not in ("Retailer", "Distributor") or amount <= 0:
        flash("Please enter a valid transfer.", "error")
        return redirect(url_for("admin"))

    con = db()
    if recipient_type == "Retailer":
        recipient = con.execute("SELECT id FROM retailers WHERE id=?", (recipient_id,)).fetchone()
    else:
        recipient = con.execute("SELECT id FROM distributors WHERE id=?", (recipient_id,)).fetchone()
    central = con.execute("SELECT balance FROM wallet WHERE id=1").fetchone()

    if not recipient:
        flash("Recipient not found.", "error")
    elif amount > central["balance"]:
        flash("Insufficient central wallet balance.", "error")
    elif recipient_type == "Retailer":
        r = con.execute("SELECT wallet_balance FROM retailers WHERE id=?", (recipient_id,)).fetchone()
        new_balance = float(r["wallet_balance"] or 0) + amount
        con.execute("UPDATE retailers SET wallet_balance=? WHERE id=?", (new_balance, recipient_id))
        con.execute("UPDATE wallet SET balance=balance-? WHERE id=1", (amount,))
        con.execute(
            "INSERT INTO wallet_transfers(recipient_type,recipient_id,amount,note) VALUES(?,?,?,?)",
            (recipient_type, recipient_id, amount, note or "Admin manual credit")
        )
        con.execute(
            "INSERT INTO retailer_wallet_ledger(retailer_id,amount,balance_after,type,note) VALUES(?,?,?,?,?)",
            (recipient_id, amount, new_balance, "Admin Credit", note or "Admin manual credit")
        )
        con.commit()
        flash(f"₹{amount:,.2f} added to retailer wallet.", "success")
    else:
        con.execute("UPDATE wallet SET balance=balance-? WHERE id=1", (amount,))
        con.execute(
            "INSERT INTO wallet_transfers(recipient_type,recipient_id,amount,note) VALUES(?,?,?,?)",
            (recipient_type, recipient_id, amount, note or None)
        )
        con.commit()
        flash(f"₹{amount:,.2f} transfer recorded.", "success")
    con.close()
    return redirect(url_for("admin"))

@app.post("/admin/retailer-password/<int:retailer_id>")
@admin_required
def admin_retailer_password(retailer_id):
    password = request.form.get("password", "")
    if len(password) < 6:
        flash("Retailer password must be at least 6 characters.", "error")
        return redirect(url_for("admin"))
    con = db()
    retailer = con.execute("SELECT username FROM retailers WHERE id=?", (retailer_id,)).fetchone()
    if not retailer:
        con.close()
        flash("Retailer not found.", "error")
        return redirect(url_for("admin"))
    con.execute("UPDATE retailers SET password_hash=? WHERE id=?", (hash_password(password), retailer_id))
    con.commit(); con.close()
    flash(f"Password changed for {retailer['username']}.", "success")
    return redirect(url_for("admin"))

@app.post("/admin/service-charge")
@admin_required
def update_service_charge():
    service = request.form.get("service", "").strip()
    try:
        charge = float(request.form.get("charge", "0"))
    except ValueError:
        charge = -1
    if service not in SERVICES or charge < 0:
        flash("Invalid service charge.", "error")
        return redirect(url_for("admin"))
    con = db()
    con.execute("INSERT INTO service_charges(service,charge) VALUES(?,?) ON CONFLICT(service) DO UPDATE SET charge=excluded.charge", (service,charge))
    con.commit()
    con.close()
    flash(f"{service} ka charge ₹{charge:,.2f} set ho gaya.", "success")
    return redirect(url_for("admin"))

@app.post("/admin/wallet-topup/<int:topup_id>/<action>")
@admin_required
def review_topup(topup_id, action):
    if action not in ("approve", "reject"):
        abort(400)

    con = db()
    topup = con.execute("SELECT * FROM wallet_topups WHERE id=?", (topup_id,)).fetchone()
    if not topup:
        con.close()
        flash("Top-up request not found.", "error")
        return redirect(url_for("admin"))

    if topup["status"] != "Pending":
        con.close()
        flash("This top-up request has already been processed.", "error")
        return redirect(url_for("admin"))

    note = request.form.get("admin_note", "").strip() or None

    if action == "reject":
        con.execute(
            "UPDATE wallet_topups SET status='Rejected', admin_note=?, processed_at=CURRENT_TIMESTAMP WHERE id=?",
            (note, topup_id)
        )
        con.commit()
        con.close()
        flash("Top-up request rejected.", "success")
        return redirect(url_for("admin"))

    retailer = con.execute(
        "SELECT wallet_balance FROM retailers WHERE id=?", (topup["retailer_id"],)
    ).fetchone()
    if not retailer:
        con.close()
        flash("Retailer not found.", "error")
        return redirect(url_for("admin"))

    new_balance = float(retailer["wallet_balance"] or 0) + float(topup["amount"])
    con.execute(
        "UPDATE retailers SET wallet_balance=? WHERE id=?",
        (new_balance, topup["retailer_id"])
    )
    con.execute(
        "INSERT INTO retailer_wallet_ledger(retailer_id,amount,balance_after,type,reference_id,note) VALUES(?,?,?,?,?,?)",
        (topup["retailer_id"], topup["amount"], new_balance, "QR Top-up", topup_id, note or "Admin approved QR payment")
    )
    con.execute(
        "UPDATE wallet_topups SET status='Approved', admin_note=?, processed_at=CURRENT_TIMESTAMP WHERE id=?",
        (note, topup_id)
    )
    con.commit()
    con.close()
    flash(f"₹{float(topup['amount']):,.2f} added to retailer wallet.", "success")
    return redirect(url_for("admin"))

@app.post("/retailer/presence")
@retailer_required
def retailer_presence_update():
    service = request.form.get("service", "").strip()
    if service and service not in SERVICES:
        service = ""
    con = db()
    con.execute(
        """INSERT INTO retailer_presence(retailer_id,service,last_seen,online) VALUES(?,?,CURRENT_TIMESTAMP,1)
           ON CONFLICT(retailer_id) DO UPDATE SET service=excluded.service,last_seen=CURRENT_TIMESTAMP,online=1""",
        (session["retailer_id"], service or None)
    )
    con.commit(); con.close()
    return ("ok", 200)

@app.post("/retailer/presence/offline")
@retailer_required
def retailer_presence_offline():
    con = db()
    con.execute("UPDATE retailer_presence SET online=0,last_seen=CURRENT_TIMESTAMP WHERE retailer_id=?", (session["retailer_id"],))
    con.commit(); con.close()
    return ("ok", 200)

@app.get("/admin/retailer-presence")
@admin_required
def admin_retailer_presence():
    con = db()
    rows = con.execute("""
        SELECT r.id, r.name, r.username, r.phone, p.service, p.last_seen,
               CASE WHEN p.retailer_id IS NOT NULL AND p.online=1
                         AND p.last_seen >= datetime('now','-30 seconds')
                    THEN 1 ELSE 0 END AS is_online
        FROM retailers r LEFT JOIN retailer_presence p ON p.retailer_id=r.id
        ORDER BY r.id
    """).fetchall()
    con.close()
    return {"retailers": [dict(r) for r in rows]}

@app.get("/retailer")
@retailer_required
def retailer_dashboard():
    con = db()
    retailer = con.execute("SELECT * FROM retailers WHERE id=?", (session["retailer_id"],)).fetchone()
    topups = con.execute(
        "SELECT * FROM wallet_topups WHERE retailer_id=? ORDER BY id DESC LIMIT 30",
        (session["retailer_id"],)
    ).fetchall()
    requests = con.execute(
        "SELECT * FROM retailer_requests WHERE retailer_id=? ORDER BY id DESC LIMIT 30",
        (session["retailer_id"],)
    ).fetchall()
    ledger = con.execute(
        "SELECT * FROM retailer_wallet_ledger WHERE retailer_id=? ORDER BY id DESC LIMIT 30",
        (session["retailer_id"],)
    ).fetchall()
    service_charges = con.execute("SELECT service,charge FROM service_charges ORDER BY service").fetchall()
    con.close()
    if not retailer:
        session.clear()
        return redirect(url_for("retailer_login"))
    service_icons = {
        "Aadhaar Name Update Assistance":"🪪", "Aadhaar DOB Update Assistance":"📅",
        "Aadhaar Full Name Update Assistance":"👤", "Birth Certificate PDF Download Assistance":"👶",
        "Voter ID Download Assistance":"🗳️", "Voter Number Link Assistance":"🔗",
        "PAN Card":"💳", "Income/Caste/Residence Certificate":"📜",
        "Online Form / Application":"📝", "Print / Scan / Photocopy":"🖨️", "Other":"📂"
    }
    return render_template("retailer.html", retailer=retailer, topups=topups, requests=requests, ledger=ledger, service_charges=service_charges, services=SERVICES, service_fields=SERVICE_FIELDS, service_icons=service_icons, service_charge=0, min_topup=MIN_TOPUP, min_required_balance=MIN_REQUIRED_BALANCE)

@app.post("/retailer/topup")
@retailer_required
def retailer_topup():
    try:
        amount = float(request.form.get("amount", "0"))
    except ValueError:
        amount = 0
    transaction_id = request.form.get("transaction_id", "").strip()

    if amount < MIN_TOPUP:
        flash(f"Minimum wallet add amount is ₹{MIN_TOPUP:.0f}.", "error")
        return redirect(url_for("retailer_dashboard"))
    if not transaction_id or len(transaction_id) > 100:
        flash("Please enter a valid Transaction ID / UTR.", "error")
        return redirect(url_for("retailer_dashboard"))

    con = db()
    existing = con.execute(
        "SELECT id FROM wallet_topups WHERE transaction_id=?", (transaction_id,)
    ).fetchone()
    if existing:
        con.close()
        flash("This Transaction ID has already been submitted.", "error")
        return redirect(url_for("retailer_dashboard"))

    con.execute(
        "INSERT INTO wallet_topups(retailer_id,amount,transaction_id) VALUES(?,?,?)",
        (session["retailer_id"], amount, transaction_id)
    )
    con.commit()
    con.close()
    flash("Top-up request submitted. Admin approval is required.", "success")
    return redirect(url_for("retailer_dashboard"))

@app.post("/retailer/service-request")
@retailer_required
def retailer_service_request():
    name=request.form.get("customer_name","").strip()
    phone=request.form.get("mobile","").strip()
    service=request.form.get("service","").strip()
    extra=request.form.get("message","").strip()
    if not name or not phone or service not in SERVICES:
        flash("Please fill all required fields correctly.","error")
        return redirect(url_for("retailer_dashboard"))
    details=[]
    for key,label,input_type,required in SERVICE_FIELDS.get(service,[]):
        value=request.form.get(key,"").strip()
        if required and not value:
            flash(f"{label} is required for this service.","error")
            return redirect(url_for("retailer_dashboard"))
        if value: details.append(f"{label}: {value}")
    if extra: details.append(f"Message: {extra}")
    details_text=" | ".join(details)
    con=db()
    retailer=con.execute("SELECT wallet_balance FROM retailers WHERE id=?",(session["retailer_id"],)).fetchone()
    row=con.execute("SELECT charge FROM service_charges WHERE service=?",(service,)).fetchone()
    charge=float(row["charge"]) if row else 0.0
    balance=float(retailer["wallet_balance"] or 0)
    if balance-charge < MIN_REQUIRED_BALANCE:
        con.close()
        flash(f"Minimum ₹{MIN_REQUIRED_BALANCE:.0f} balance must remain. Service charge: ₹{charge:,.2f}. Current balance: ₹{balance:,.2f}.","error")
        return redirect(url_for("retailer_dashboard"))
    new_balance=balance-charge
    cur=con.execute("INSERT INTO retailer_requests(retailer_id,name,phone,service,message,charge,status) VALUES(?,?,?,?,?,?, 'Pending')",(session["retailer_id"],name,phone,service,details_text,charge))
    req_id=cur.lastrowid
    con.execute("UPDATE retailers SET wallet_balance=? WHERE id=?",(new_balance,session["retailer_id"]))
    con.execute("INSERT INTO retailer_wallet_ledger(retailer_id,amount,balance_after,type,reference_id,note) VALUES(?,?,?,?,?,?)",(session["retailer_id"],-charge,new_balance,"Service Charge",req_id,service))
    con.commit(); con.close()
    flash(f"Service request submitted. ₹{charge:,.2f} service charge deducted.","success")
    return redirect(url_for("retailer_dashboard"))

@app.post("/admin/retailer-request/<int:req_id>/<action>")
@admin_required
def review_retailer_request(req_id, action):
    if action not in ("success", "reject"):
        abort(400)

    con = db()
    req = con.execute("SELECT * FROM retailer_requests WHERE id=?", (req_id,)).fetchone()
    if not req:
        con.close()
        flash("Retailer service request not found.", "error")
        return redirect(url_for("admin"))

    if req["status"] != "Pending":
        con.close()
        flash("This request has already been processed.", "error")
        return redirect(url_for("admin"))

    if action == "success":
        pdf = request.files.get("pdf")
        if not pdf or not pdf.filename:
            con.close()
            flash("PDF upload karke hi Successfully Approved karein.", "error")
            return redirect(url_for("admin"))
        filename = secure_filename(pdf.filename)
        if not filename or "." not in filename or filename.rsplit(".", 1)[1].lower() not in ALLOWED_PDF_EXTENSIONS:
            con.close()
            flash("Sirf PDF file upload karein.", "error")
            return redirect(url_for("admin"))
        pdf.seek(0, os.SEEK_END)
        size = pdf.tell()
        pdf.seek(0)
        if size > MAX_PDF_SIZE:
            con.close()
            flash("PDF maximum 10 MB ki ho sakti hai.", "error")
            return redirect(url_for("admin"))
        stored_name = f"request_{req_id}_{uuid.uuid4().hex}.pdf"
        pdf.save(os.path.join(UPLOAD_DIR, stored_name))
        con.execute("UPDATE retailer_requests SET status='Success', pdf_filename=? WHERE id=?", (stored_name, req_id))
        con.commit()
        con.close()
        flash("PDF upload ho gayi aur request Successfully Approved hai.", "success")
        return redirect(url_for("admin"))

    retailer = con.execute(
        "SELECT wallet_balance FROM retailers WHERE id=?", (req["retailer_id"],)
    ).fetchone()
    new_balance = float(retailer["wallet_balance"] or 0) + float(req["charge"])
    con.execute(
        "UPDATE retailers SET wallet_balance=? WHERE id=?",
        (new_balance, req["retailer_id"])
    )
    con.execute(
        """INSERT INTO retailer_wallet_ledger
           (retailer_id,amount,balance_after,type,reference_id,note)
           VALUES(?,?,?,?,?,?)""",
        (req["retailer_id"], req["charge"], new_balance,
         "Service Refund", req_id, "Admin rejected service request")
    )
    con.execute("UPDATE retailer_requests SET status='Rejected' WHERE id=?", (req_id,))
    con.commit()
    con.close()
    flash(f"Request rejected and ₹{float(req['charge']):,.2f} refunded to retailer wallet.", "success")
    return redirect(url_for("admin"))

@app.get("/admin/retailer-request/<int:req_id>/download")
@admin_required
def admin_download_retailer_pdf(req_id):
    con = db()
    req = con.execute("SELECT * FROM retailer_requests WHERE id=?", (req_id,)).fetchone()
    con.close()
    if not req or not req["pdf_filename"]:
        abort(404)
    path = os.path.join(UPLOAD_DIR, os.path.basename(req["pdf_filename"]))
    if not os.path.isfile(path):
        abort(404)
    return send_from_directory(UPLOAD_DIR, os.path.basename(path), as_attachment=False, mimetype="application/pdf")

@app.get("/retailer/request/<int:req_id>/download")
@retailer_required
def download_retailer_pdf(req_id):
    con = db()
    req = con.execute(
        "SELECT * FROM retailer_requests WHERE id=? AND retailer_id=?",
        (req_id, session["retailer_id"])
    ).fetchone()
    con.close()
    if not req or req["status"] != "Success" or not req["pdf_filename"]:
        abort(404)
    path = os.path.join(UPLOAD_DIR, os.path.basename(req["pdf_filename"]))
    if not os.path.isfile(path):
        abort(404)
    download_name = secure_filename(f"{req['service']}_{req_id}.pdf") or f"service_{req_id}.pdf"
    return send_from_directory(UPLOAD_DIR, os.path.basename(path), as_attachment=True, download_name=download_name)

@app.post("/admin/status/<int:req_id>")
@admin_required
def update_status(req_id):
    status = request.form.get("status", "")
    if status not in ("Pending", "Contacted", "Completed", "Cancelled"):
        abort(400)
    con = db()
    con.execute("UPDATE requests SET status=? WHERE id=?", (status, req_id))
    con.commit()
    con.close()
    return redirect(request.referrer or url_for("admin"))

@app.post("/admin/delete/<int:req_id>")
@admin_required
def delete_request(req_id):
    con = db()
    con.execute("DELETE FROM requests WHERE id=?", (req_id,))
    con.commit()
    con.close()
    return redirect(request.referrer or url_for("admin"))

@app.get("/admin/export.csv")
@admin_required
def export_csv():
    con = db()
    rows = con.execute(
        "SELECT id,name,phone,service,preferred_date,message,status,created_at "
        "FROM requests ORDER BY id DESC"
    ).fetchall()
    con.close()
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(["ID","Name","Phone","Service","Preferred Date","Message","Status","Created At"])
    writer.writerows([list(r) for r in rows])
    return Response(
        "\ufeff" + out.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=shiva_janseva_requests.csv"}
    )

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=False)
