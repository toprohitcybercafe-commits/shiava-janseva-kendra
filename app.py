import os, csv, io, sqlite3, hashlib, secrets
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, flash, Response, abort

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "shiva_janseva.db")
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "CHANGE-ME-IN-PRODUCTION")
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax", SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "0") == "1")

SERVICES = [
    "Aadhaar Name Update Assistance", "Aadhaar DOB Update Assistance", "Aadhaar Full Name Update Assistance",
    "Birth Certificate PDF Download Assistance", "Voter ID Download Assistance", "Voter Number Link Assistance",
    "PAN Card", "Income/Caste/Residence Certificate", "Online Form / Application", "Print / Scan / Photocopy", "Other",
]
SERVICE_CHARGE = 100.0  # Default demo/internal charge per retailer service request.


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


def ensure_column(con, table, column, definition):
    cols = {r[1] for r in con.execute(f"PRAGMA table_info({table})").fetchall()}
    if column not in cols:
        con.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")


def init_db():
    con = db()
    con.executescript("""
    CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, must_change INTEGER NOT NULL DEFAULT 1);
    CREATE TABLE IF NOT EXISTS requests (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, phone TEXT NOT NULL, service TEXT NOT NULL, preferred_date TEXT, message TEXT, status TEXT NOT NULL DEFAULT 'Pending', created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
    CREATE TABLE IF NOT EXISTS retailers (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, phone TEXT NOT NULL, username TEXT, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
    CREATE TABLE IF NOT EXISTS distributors (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, phone TEXT NOT NULL, username TEXT, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
    CREATE TABLE IF NOT EXISTS wallet (id INTEGER PRIMARY KEY CHECK(id=1), balance REAL NOT NULL DEFAULT 1000000);
    CREATE TABLE IF NOT EXISTS wallet_transfers (id INTEGER PRIMARY KEY AUTOINCREMENT, recipient_type TEXT NOT NULL, recipient_id INTEGER NOT NULL, amount REAL NOT NULL, note TEXT, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
    """)
    ensure_column(con, "retailers", "password_hash", "TEXT")
    ensure_column(con, "retailers", "balance", "REAL NOT NULL DEFAULT 0")
    ensure_column(con, "requests", "retailer_id", "INTEGER")
    ensure_column(con, "requests", "amount", "REAL NOT NULL DEFAULT 0")
    ensure_column(con, "requests", "refunded", "INTEGER NOT NULL DEFAULT 0")
    if not con.execute("SELECT 1 FROM users WHERE username='admin'").fetchone():
        con.execute("INSERT INTO users(username,password_hash,must_change) VALUES(?,?,1)", ("admin", hash_password("Shiva@2026!")))
    if not con.execute("SELECT 1 FROM wallet WHERE id=1").fetchone():
        con.execute("INSERT INTO wallet(id,balance) VALUES(1,1000000)")
    con.commit(); con.close()

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
    return {"business_name": "Shiva Janseva Kendra", "location": "Roshnabad", "phone": "7505955205", "services": SERVICES, "service_charge": SERVICE_CHARGE}


@app.route("/")
def index():
    return render_template("index.html")


@app.post("/request")
def service_request():
    name=request.form.get("name","").strip(); phone=request.form.get("phone","").strip(); service=request.form.get("service","").strip(); date=request.form.get("preferred_date","").strip(); message=request.form.get("message","").strip()
    if not name or not phone or service not in SERVICES:
        flash("Please fill the required fields correctly.", "error"); return redirect(url_for("index"))
    con=db(); con.execute("INSERT INTO requests(name,phone,service,preferred_date,message,status) VALUES(?,?,?,?,?,?)", (name,phone,service,date,message,"Pending")); con.commit(); con.close()
    flash("Request submitted successfully. Kendra will contact you.", "success"); return redirect(url_for("index"))


@app.route("/login", methods=["GET","POST"])
def login():
    if request.method=="POST":
        username=request.form.get("username","").strip(); password=request.form.get("password","")
        con=db(); user=con.execute("SELECT * FROM users WHERE username=?",(username,)).fetchone(); con.close()
        if user and verify_password(password,user["password_hash"]):
            session.clear(); session["admin_id"]=user["id"]; session["username"]=user["username"]; session["must_change"]=bool(user["must_change"])
            if user["must_change"]: return redirect(url_for("change_password"))
            return redirect(url_for("admin"))
        flash("Invalid login details.","error")
    return render_template("login.html")


@app.route("/retailer-login", methods=["GET","POST"])
def retailer_login():
    if request.method=="POST":
        username=request.form.get("username","").strip(); password=request.form.get("password","")
        con=db(); r=con.execute("SELECT * FROM retailers WHERE username=?",(username,)).fetchone(); con.close()
        if r and r["password_hash"] and verify_password(password,r["password_hash"]):
            session.clear(); session["retailer_id"]=r["id"]; session["retailer_username"]=r["username"]; return redirect(url_for("retailer_dashboard"))
        flash("Invalid retailer ID or password.","error")
    return render_template("retailer_login.html")


@app.get("/retailer/logout")
def retailer_logout():
    session.clear(); return redirect(url_for("index"))


@app.get("/retailer")
@retailer_required
def retailer_dashboard():
    con=db(); r=con.execute("SELECT * FROM retailers WHERE id=?",(session["retailer_id"],)).fetchone(); rows=con.execute("SELECT * FROM requests WHERE retailer_id=? ORDER BY id DESC LIMIT 100",(r["id"],)).fetchall(); con.close()
    if not r: session.clear(); return redirect(url_for("retailer_login"))
    return render_template("retailer_dashboard.html", retailer=r, rows=rows)


@app.post("/retailer/request")
@retailer_required
def retailer_request():
    service=request.form.get("service","").strip(); name=request.form.get("name","").strip(); phone=request.form.get("phone","").strip(); date=request.form.get("preferred_date","").strip(); message=request.form.get("message","").strip()
    if service not in SERVICES or not name or not phone:
        flash("Name, mobile and valid service are required.","error"); return redirect(url_for("retailer_dashboard"))
    con=db(); r=con.execute("SELECT * FROM retailers WHERE id=?",(session["retailer_id"],)).fetchone()
    if not r or r["balance"] < SERVICE_CHARGE:
        con.close(); flash(f"Insufficient retailer balance. Required: ₹{SERVICE_CHARGE:,.2f}","error"); return redirect(url_for("retailer_dashboard"))
    con.execute("UPDATE retailers SET balance=balance-? WHERE id=?",(SERVICE_CHARGE,r["id"]))
    con.execute("INSERT INTO requests(name,phone,service,preferred_date,message,status,retailer_id,amount,refunded) VALUES(?,?,?,?,?,?,?,?,0)",(name,phone,service,date,message,"Pending",r["id"],SERVICE_CHARGE))
    con.commit(); con.close(); flash(f"Request submitted. ₹{SERVICE_CHARGE:,.2f} deducted; refund will be automatic if Admin rejects it.","success"); return redirect(url_for("retailer_dashboard"))


@app.get("/change-password")
@admin_required
def change_password():
    return render_template("change.html")


@app.post("/change-password")
@admin_required
def change_password_post():
    new=request.form.get("new_password",""); confirm=request.form.get("confirm_password","")
    if len(new)<10: flash("Password must be at least 10 characters.","error")
    elif new!=confirm: flash("Passwords do not match.","error")
    else:
        con=db(); con.execute("UPDATE users SET password_hash=?,must_change=0 WHERE id=?",(hash_password(new),session["admin_id"])); con.commit(); con.close(); session["must_change"]=False; flash("Password changed successfully.","success"); return redirect(url_for("admin"))
    return render_template("change.html")


@app.get("/logout")
def logout(): session.clear(); return redirect(url_for("index"))


@app.get("/admin")
@admin_required
def admin():
    if session.get("must_change"): return redirect(url_for("change_password"))
    q=request.args.get("q","").strip(); status=request.args.get("status","").strip(); con=db(); where=[]; args=[]
    if q: where.append("(name LIKE ? OR phone LIKE ? OR service LIKE ?)"); args += [f"%{q}%",f"%{q}%",f"%{q}%"]
    if status in ("Pending","Success","Rejected"): where.append("status=?"); args.append(status)
    clause=(" WHERE "+" AND ".join(where)) if where else ""
    rows=con.execute("SELECT requests.*,retailers.name AS retailer_name FROM requests LEFT JOIN retailers ON requests.retailer_id=retailers.id"+clause+" ORDER BY requests.id DESC",args).fetchall()
    stats={s:con.execute("SELECT COUNT(*) FROM requests WHERE status=?",(s,)).fetchone()[0] for s in ("Pending","Success","Rejected")}
    retailers=con.execute("SELECT * FROM retailers ORDER BY id DESC").fetchall(); distributors=con.execute("SELECT * FROM distributors ORDER BY id DESC").fetchall(); wallet=con.execute("SELECT balance FROM wallet WHERE id=1").fetchone()["balance"]
    transfers=con.execute("SELECT wt.*,CASE WHEN wt.recipient_type='Retailer' THEN r.name ELSE d.name END AS recipient_name FROM wallet_transfers wt LEFT JOIN retailers r ON wt.recipient_type='Retailer' AND wt.recipient_id=r.id LEFT JOIN distributors d ON wt.recipient_type='Distributor' AND wt.recipient_id=d.id ORDER BY wt.id DESC LIMIT 20").fetchall(); con.close()
    return render_template("admin.html",rows=rows,stats=stats,q=q,selected_status=status,retailers=retailers,distributors=distributors,wallet=wallet,transfers=transfers)


@app.post("/admin/add-retailer")
@admin_required
def add_retailer():
    name=request.form.get("name","").strip(); phone=request.form.get("phone","").strip(); username=request.form.get("username","").strip(); password=request.form.get("password","")
    if not name or not phone or not username or len(password)<8: flash("Name, mobile, username and password (8+ characters) are required.","error")
    else:
        con=db()
        try:
            con.execute("INSERT INTO retailers(name,phone,username,password_hash,balance) VALUES(?,?,?,?,0)",(name,phone,username,hash_password(password))); con.commit(); flash("Retailer added with login successfully.","success")
        except sqlite3.IntegrityError: flash("This retailer username may already exist.","error")
        finally: con.close()
    return redirect(url_for("admin"))


@app.post("/admin/add-distributor")
@admin_required
def add_distributor():
    name=request.form.get("name","").strip(); phone=request.form.get("phone","").strip(); username=request.form.get("username","").strip()
    if not name or not phone: flash("Distributor name and mobile are required.","error")
    else:
        con=db(); con.execute("INSERT INTO distributors(name,phone,username) VALUES(?,?,?)",(name,phone,username or None)); con.commit(); con.close(); flash("Distributor added successfully.","success")
    return redirect(url_for("admin"))


@app.post("/admin/transfer")
@admin_required
def transfer_balance():
    recipient_type=request.form.get("recipient_type","")
    try: recipient_id=int(request.form.get("recipient_id","0")); amount=float(request.form.get("amount","0"))
    except ValueError: recipient_id,amount=0,0
    note=request.form.get("note","").strip()
    if recipient_type not in ("Retailer","Distributor") or amount<=0: flash("Please enter a valid transfer.","error"); return redirect(url_for("admin"))
    con=db(); table="retailers" if recipient_type=="Retailer" else "distributors"; recipient=con.execute(f"SELECT id FROM {table} WHERE id=?",(recipient_id,)).fetchone(); wallet=con.execute("SELECT balance FROM wallet WHERE id=1").fetchone()
    if not recipient: flash("Recipient not found.","error")
    elif amount>wallet["balance"]: flash("Insufficient wallet balance.","error")
    else:
        con.execute("UPDATE wallet SET balance=balance-? WHERE id=1",(amount,))
        if recipient_type=="Retailer": con.execute("UPDATE retailers SET balance=balance+? WHERE id=?",(amount,recipient_id))
        con.execute("INSERT INTO wallet_transfers(recipient_type,recipient_id,amount,note) VALUES(?,?,?,?)",(recipient_type,recipient_id,amount,note or None)); con.commit(); flash(f"₹{amount:,.2f} transferred to {recipient_type.lower()}.","success")
    con.close(); return redirect(url_for("admin"))


@app.post("/admin/status/<int:req_id>")
@admin_required
def update_status(req_id):
    status=request.form.get("status","")
    if status not in ("Pending","Success","Rejected"): abort(400)
    con=db(); r=con.execute("SELECT * FROM requests WHERE id=?",(req_id,)).fetchone()
    if not r: con.close(); abort(404)
    if r["status"]=="Rejected" and status!="Rejected": con.close(); flash("A rejected request cannot be reopened.","error"); return redirect(request.referrer or url_for("admin"))
    if status=="Rejected" and r["retailer_id"] and not r["refunded"] and r["amount"]>0:
        con.execute("UPDATE retailers SET balance=balance+? WHERE id=?",(r["amount"],r["retailer_id"]))
        con.execute("UPDATE requests SET status='Rejected',refunded=1 WHERE id=?",(req_id,))
        con.commit(); flash(f"Rejected. ₹{r['amount']:,.2f} automatically refunded to retailer.","success")
    else:
        con.execute("UPDATE requests SET status=? WHERE id=?",(status,req_id)); con.commit()
        flash(f"Request #{req_id} marked {status}.","success")
    con.close(); return redirect(request.referrer or url_for("admin"))


@app.post("/admin/delete/<int:req_id>")
@admin_required
def delete_request(req_id):
    con=db(); con.execute("DELETE FROM requests WHERE id=?",(req_id,)); con.commit(); con.close(); return redirect(request.referrer or url_for("admin"))


@app.get("/admin/export.csv")
@admin_required
def export_csv():
    con=db(); rows=con.execute("SELECT id,name,phone,service,preferred_date,message,status,retailer_id,amount,refunded,created_at FROM requests ORDER BY id DESC").fetchall(); con.close(); out=io.StringIO(); writer=csv.writer(out); writer.writerow(["ID","Name","Phone","Service","Preferred Date","Message","Status","Retailer ID","Amount","Refunded","Created At"]); writer.writerows([list(r) for r in rows]); return Response("\ufeff"+out.getvalue(),mimetype="text/csv",headers={"Content-Disposition":"attachment; filename=shiva_janseva_requests.csv"})


if __name__ == "__main__": app.run(host="0.0.0.0",port=int(os.environ.get("PORT",5000)),debug=False)
