import os, csv, io, sqlite3, hashlib, secrets
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, flash, Response, abort

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "shiva_janseva.db")
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "CHANGE-ME-IN-PRODUCTION")
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "0") == "1",
)

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
        username TEXT,
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
    """)
    if not con.execute("SELECT 1 FROM users WHERE username='admin'").fetchone():
        con.execute("INSERT INTO users(username,password_hash,must_change) VALUES(?,?,1)",
                    ("admin", hash_password("Shiva@2026!")))
    if not con.execute("SELECT 1 FROM wallet WHERE id=1").fetchone():
        con.execute("INSERT INTO wallet(id,balance) VALUES(1,1000000)")
    con.commit()
    con.close()


def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("admin_id"):
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapper


@app.context_processor
def globals():
    return {
        "business_name": "Shiva Janseva Kendra",
        "location": "Roshnabad",
        "phone": "7505955205",
        "services": SERVICES,
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
    con.execute("INSERT INTO requests(name,phone,service,preferred_date,message) VALUES(?,?,?,?,?)",
                (name, phone, service, date, message))
    con.commit(); con.close()
    flash("Request submitted successfully. Kendra will contact you.", "success")
    return redirect(url_for("index"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        con = db(); user = con.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone(); con.close()
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


@app.get("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


@app.route("/change-password", methods=["GET", "POST"])
@login_required
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
            con.execute("UPDATE users SET password_hash=?, must_change=0 WHERE id=?",
                        (hash_password(new), session["admin_id"]))
            con.commit(); con.close()
            session["must_change"] = False
            flash("Password changed successfully.", "success")
            return redirect(url_for("admin"))
    return render_template("change.html")


@app.get("/admin")
@login_required
def admin():
    if session.get("must_change"):
        return redirect(url_for("change_password"))
    q = request.args.get("q", "").strip()
    status = request.args.get("status", "").strip()
    con = db()
    where=[]; args=[]
    if q:
        where.append("(name LIKE ? OR phone LIKE ? OR service LIKE ?)")
        args += [f"%{q}%", f"%{q}%", f"%{q}%"]
    if status in ("Pending", "Contacted", "Completed", "Cancelled"):
        where.append("status=?"); args.append(status)
    clause = (" WHERE " + " AND ".join(where)) if where else ""
    rows = con.execute("SELECT * FROM requests" + clause + " ORDER BY id DESC", args).fetchall()
    stats = {s: con.execute("SELECT COUNT(*) FROM requests WHERE status=?", (s,)).fetchone()[0]
             for s in ("Pending", "Contacted", "Completed", "Cancelled")}
    retailers = con.execute("SELECT * FROM retailers ORDER BY id DESC").fetchall()
    distributors = con.execute("SELECT * FROM distributors ORDER BY id DESC").fetchall()
    wallet = con.execute("SELECT balance FROM wallet WHERE id=1").fetchone()["balance"]
    transfers = con.execute("""SELECT wt.*, 
        CASE WHEN wt.recipient_type='Retailer' THEN r.name ELSE d.name END AS recipient_name
        FROM wallet_transfers wt
        LEFT JOIN retailers r ON wt.recipient_type='Retailer' AND wt.recipient_id=r.id
        LEFT JOIN distributors d ON wt.recipient_type='Distributor' AND wt.recipient_id=d.id
        ORDER BY wt.id DESC LIMIT 20""").fetchall()
    con.close()
    return render_template("admin.html", rows=rows, stats=stats, q=q,
                           selected_status=status, retailers=retailers,
                           distributors=distributors, wallet=wallet, transfers=transfers)


@app.post("/admin/add-retailer")
@login_required
def add_retailer():
    name = request.form.get("name", "").strip()
    phone = request.form.get("phone", "").strip()
    username = request.form.get("username", "").strip()
    if not name or not phone:
        flash("Retailer name and mobile are required.", "error")
    else:
        con = db(); con.execute("INSERT INTO retailers(name,phone,username) VALUES(?,?,?)", (name, phone, username or None)); con.commit(); con.close()
        flash("Retailer added successfully.", "success")
    return redirect(url_for("admin"))


@app.post("/admin/add-distributor")
@login_required
def add_distributor():
    name = request.form.get("name", "").strip()
    phone = request.form.get("phone", "").strip()
    username = request.form.get("username", "").strip()
    if not name or not phone:
        flash("Distributor name and mobile are required.", "error")
    else:
        con = db(); con.execute("INSERT INTO distributors(name,phone,username) VALUES(?,?,?)", (name, phone, username or None)); con.commit(); con.close()
        flash("Distributor added successfully.", "success")
    return redirect(url_for("admin"))


@app.post("/admin/transfer")
@login_required
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
    table = "retailers" if recipient_type == "Retailer" else "distributors"
    recipient = con.execute(f"SELECT id FROM {table} WHERE id=?", (recipient_id,)).fetchone()
    wallet = con.execute("SELECT balance FROM wallet WHERE id=1").fetchone()
    if not recipient:
        flash("Recipient not found.", "error")
    elif amount > wallet["balance"]:
        flash("Insufficient wallet balance.", "error")
    else:
        con.execute("UPDATE wallet SET balance=balance-? WHERE id=1", (amount,))
        con.execute("INSERT INTO wallet_transfers(recipient_type,recipient_id,amount,note) VALUES(?,?,?,?)",
                    (recipient_type, recipient_id, amount, note or None))
        con.commit()
        flash(f"₹{amount:,.2f} transfer recorded to {recipient_type.lower()}.", "success")
    con.close()
    return redirect(url_for("admin"))


@app.post("/admin/status/<int:req_id>")
@login_required
def update_status(req_id):
    status = request.form.get("status", "")
    if status not in ("Pending", "Contacted", "Completed", "Cancelled"):
        abort(400)
    con=db(); con.execute("UPDATE requests SET status=? WHERE id=?", (status, req_id)); con.commit(); con.close()
    return redirect(request.referrer or url_for("admin"))


@app.post("/admin/delete/<int:req_id>")
@login_required
def delete_request(req_id):
    con=db(); con.execute("DELETE FROM requests WHERE id=?", (req_id,)); con.commit(); con.close()
    return redirect(request.referrer or url_for("admin"))


@app.get("/admin/export.csv")
@login_required
def export_csv():
    con=db()
    rows=con.execute("SELECT id,name,phone,service,preferred_date,message,status,created_at FROM requests ORDER BY id DESC").fetchall()
    con.close()
    out=io.StringIO(); writer=csv.writer(out)
    writer.writerow(["ID","Name","Phone","Service","Preferred Date","Message","Status","Created At"])
    writer.writerows([list(r) for r in rows])
    return Response("\ufeff"+out.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition":"attachment; filename=shiva_janseva_requests.csv"})


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=False)
