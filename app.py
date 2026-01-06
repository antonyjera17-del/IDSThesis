from flask import Flask, render_template, request, redirect, jsonify, send_file
import pandas as pd
import joblib
import numpy as np
import io
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from flask_login import LoginManager, login_user, login_required, UserMixin, logout_user, current_user
from flask_bcrypt import Bcrypt
from functools import wraps
import sqlite3
from datetime import datetime
import re
import sqlite3
from datetime import datetime
from flask import session
import os
from flask_mail import Mail, Message
import os
from dotenv import load_dotenv
load_dotenv()


app = Flask(__name__)
app.config["MAIL_SERVER"] = "smtp.gmail.com"
app.config["MAIL_PORT"] = 587
app.config["MAIL_USE_TLS"] = True

app.config["MAIL_USERNAME"] = os.getenv("IDS_MAIL_USER")
app.config["MAIL_PASSWORD"] = os.getenv("IDS_MAIL_PASS")

ALERT_TO_EMAIL = os.getenv("IDS_ALERT_TO")

mail = Mail(app)
app.secret_key = "ids-secret-key"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "ids_settings.db")


def init_settings_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )
    """)
    cur.execute("INSERT OR IGNORE INTO settings(key, value) VALUES('threshold', '0.50')")
    conn.commit()
    conn.close()

def get_threshold() -> float:
    # Safety: always ensure table exists before reading
    init_settings_db()

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT value FROM settings WHERE key='threshold'")
    row = cur.fetchone()
    conn.close()
    return float(row[0]) if row else 0.50

def set_threshold(val: float):
    init_settings_db()

    val = max(0.05, min(0.95, float(val)))
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("INSERT OR REPLACE INTO settings(key, value) VALUES('threshold', ?)", (str(val),))
    conn.commit()
    conn.close()

# Run once at startup (optional now, but fine)
init_settings_db()

print("Using settings DB:", DB_PATH)


bcrypt = Bcrypt(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

# Load ML model
model = joblib.load("malicious_detector.pkl")

#ml probablity helper
def get_malicious_probability(model, X: np.ndarray) -> float:
    """
    Returns probability of malicious class (0..1).
    Works for sklearn models with predict_proba.
    Falls back to decision_function if needed.
    """
    if hasattr(model, "predict_proba"):
        proba = model.predict_proba(X)
        # For binary classification, proba[:,1] is positive class
        if proba.shape[1] >= 2:
            return float(proba[0, 1])
        return float(proba[0, 0])

    if hasattr(model, "decision_function"):
        score = float(model.decision_function(X)[0])
        # Convert to probability-like value using sigmoid
        return float(1 / (1 + np.exp(-score)))

    # last resort
    pred = model.predict(X)[0]
    return 1.0 if str(pred) in ["1", "bad", "malicious"] else 0.0

# Load processed batch file (global DataFrame)
df_main = pd.read_csv("predicted_361k.csv")
if 'content' in df_main.columns:
    df_main = df_main.drop(columns=['content'])
# Normalize prediction column if necessary (support 'bad'/'good' or 1/0)
if df_main['prediction'].dtype != object:
    df_main['prediction'] = df_main['prediction'].apply(lambda x: 'bad' if x==1 else 'good')

# Ensure timestamp column exists (create dummy if not)
if 'ts' not in df_main.columns:
    df_main['ts'] = pd.NA
#-------------------Audit log--------------
DB_PATH = "audit.db"

def init_audit_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL,
            username TEXT,
            role TEXT,
            action TEXT NOT NULL,
            endpoint TEXT,
            ip TEXT,
            user_agent TEXT,
            details TEXT
        )
    """)
    conn.commit()
    conn.close()
#-----Email 
def send_alert_email(url, prob_mal, risk_score, reasons):
    try:
        if not ALERT_TO_EMAIL:
            return

        subject = f"[IDS ALERT] Malicious URL detected (Risk {risk_score}/100)"
        body = (
            f"Malicious URL detected by IDS\n\n"
            f"URL: {url}\n"
            f"Probability: {prob_mal:.4f}\n"
            f"Risk Score: {risk_score}/100\n\n"
            f"Reasons:\n- " + "\n- ".join(reasons) + "\n"
        )

        msg = Message(subject=subject,
                      sender=app.config["MAIL_USERNAME"],
                      recipients=[ALERT_TO_EMAIL])
        msg.body = body
        mail.send(msg)
    except Exception as e:
        print("Email alert failed:", e)

def write_audit(action, endpoint=None, details=None):
    try:
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()

        username = None
        role = None
        if current_user and getattr(current_user, "is_authenticated", False):
            username = current_user.id
            role = getattr(current_user, "role", None)

        ip = request.headers.get("X-Forwarded-For", request.remote_addr)
        ua = request.headers.get("User-Agent", "")

        cur.execute("""
            INSERT INTO audit_log(ts, username, role, action, endpoint, ip, user_agent, details)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            username,
            role,
            action,
            endpoint,
            ip,
            ua,
            details
        ))
        conn.commit()
        conn.close()
    except Exception:
        # Don't crash app if audit logging fails
        pass

# Call once when app starts
init_audit_db()
#Add URL explainability function
SUSPICIOUS_TLDS = {"zip", "mov", "top", "xyz", "ru", "cn", "tk", "gq", "work", "click"}

def explain_url(url: str) -> list[str]:
    reasons = []

    # 1) HTTPS missing
    if not url.lower().startswith("https://"):
        reasons.append("HTTPS not used (no encryption / weaker trust signal)")

    # 2) IP address in URL
    if re.search(r"(?:\d{1,3}\.){3}\d{1,3}", url):
        reasons.append("Contains an IP address instead of a domain (common in phishing)")

    # 3) '@' symbol
    if "@" in url:
        reasons.append("Contains '@' (can hide real destination)")

    # 4) many special chars
    special_chars = set("?=&%/;<>\"'")
    count_special = sum(1 for ch in url if ch in special_chars)
    if count_special >= 8:
        reasons.append(f"High special-character count ({count_special}) (often used in obfuscation)")

    # 5) very long URL
    if len(url) >= 120:
        reasons.append(f"Unusually long URL ({len(url)} chars)")

    # 6) many subdomains
    host_part = re.sub(r"^https?://", "", url.lower()).split("/")[0]
    if host_part.count(".") >= 4:
        reasons.append("Many subdomains (possible brand impersonation / deceptive structure)")

    # 7) encoded / obfuscated patterns
    if "%2f" in url.lower() or "%3d" in url.lower() or "%2e" in url.lower():
        reasons.append("URL contains encoded characters (possible obfuscation)")

    # 8) suspicious tld
    tld = host_part.split(".")[-1] if "." in host_part else ""
    if tld in SUSPICIOUS_TLDS:
        reasons.append(f"Suspicious/abused TLD detected: .{tld}")

    if not reasons:
        reasons.append("No obvious heuristic red flags found (classification based mainly on model features)")

    return reasons


# ---------------- AUTH USERS ----------------
users = {
    "admin": {
        "password": bcrypt.generate_password_hash("admin123").decode("utf-8"),
        "role": "admin"
    },
    "analyst": {
        "password": bcrypt.generate_password_hash("analyst123").decode("utf-8"),
        "role": "analyst"
    }
}


class User(UserMixin):
    def __init__(self, username, role):
        self.id = username
        self.role = role

@login_manager.user_loader
def load_user(user_id):
    if user_id in users:
        return User(user_id, users[user_id]["role"])
    return None

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if current_user.role != "admin":
            return "Access denied", 403
        return f(*args, **kwargs)
    return decorated

@app.route("/index")
@login_required
def index():
    return render_template("index.html", model=model)

# ---------------- HOME ----------------
@app.route("/")
def home():
    return redirect("/login")


# ---------------- LOGIN ----------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        if username in users and bcrypt.check_password_hash(users[username]["password"], password):
            user = User(username, users[username]["role"])
            login_user(user)

            write_audit("LOGIN_SUCCESS", endpoint="/login", details=f"role={users[username]['role']}")
            return redirect("/dashboard")
        else:
            write_audit("LOGIN_FAILED", endpoint="/login", details=f"username={username}")
            return render_template("login.html", error="Invalid credentials")

    return render_template("login.html")


# ---------------- LOGOUT ----------------
@app.route("/logout")
@login_required
def logout():
    write_audit("LOGOUT", endpoint="/logout")
    logout_user()
    return redirect("/login")

# ---------------- DASHBOARD ----------------
@app.route("/dashboard")
def dashboard():
    df = df_main.copy()

    malicious_count = int((df["prediction"] == "bad").sum())
    benign_count = int((df["prediction"] == "good").sum())
    total = malicious_count + benign_count
    pct_mal = round(100 * malicious_count / total, 2) if total > 0 else 0.0

    # pick best available URL length column
    if "url_length" in df.columns:
        url_len = pd.to_numeric(df["url_length"], errors="coerce").fillna(0)
    elif "url_len" in df.columns:
        url_len = pd.to_numeric(df["url_len"], errors="coerce").fillna(0)
    else:
        url_len = df["url"].astype(str).str.len()

    # optional columns fallback
    spec = pd.to_numeric(df["count_special_char"], errors="coerce").fillna(0) if "count_special_char" in df.columns else 0
    js_len = pd.to_numeric(df["js_len"], errors="coerce").fillna(0) if "js_len" in df.columns else 0
    js_obf = pd.to_numeric(df["js_obf_len"], errors="coerce").fillna(0) if "js_obf_len" in df.columns else 0

    # risk score (0..100) - explainable, thesis-friendly heuristic severity
    risk = (
        (url_len.clip(0, 200) / 200) * 35 +
        (spec.clip(0, 20) / 20) * 25 +
        (js_len.clip(0, 2000) / 2000) * 20 +
        (js_obf.clip(0, 1000) / 1000) * 20
    ).round().astype(int).clip(0, 100)

    df["risk_score"] = risk

    high_risk = int((df["risk_score"] >= 70).sum())
    avg_risk = float(df["risk_score"].mean().round(2))

    # TLD analysis
    host = df["url"].astype(str).str.replace(r"^https?://", "", regex=True).str.split("/").str[0]
    df["tld"] = host.str.split(".").str[-1].str.lower()

    top_tlds = (
        df[df["prediction"] == "bad"]
        .groupby("tld")
        .size()
        .sort_values(ascending=False)
        .head(8)
        .reset_index(name="malicious_count")
        .to_dict(orient="records")
    )

    # Top 10 highest-risk rows (triage list)
    top_urls = (
        df.sort_values("risk_score", ascending=False)
          .head(10)[["url", "prediction", "risk_score"]]
          .to_dict(orient="records")
    )

    return render_template(
        "dashboard.html",
        title="Dashboard",
        malicious=malicious_count,
        benign=benign_count,
        total=total,
        pct_mal=pct_mal,
        high_risk=high_risk,
        avg_risk=avg_risk,
        top_tlds=top_tlds,
        top_urls=top_urls
    )
#Riskdistribution
@app.route("/riskdist")
def riskdist():
    df = df_main.copy()

    if "url_length" in df.columns:
        url_len = pd.to_numeric(df["url_length"], errors="coerce").fillna(0)
    elif "url_len" in df.columns:
        url_len = pd.to_numeric(df["url_len"], errors="coerce").fillna(0)
    else:
        url_len = df["url"].astype(str).str.len()

    spec = pd.to_numeric(df["count_special_char"], errors="coerce").fillna(0) if "count_special_char" in df.columns else 0
    js_len = pd.to_numeric(df["js_len"], errors="coerce").fillna(0) if "js_len" in df.columns else 0
    js_obf = pd.to_numeric(df["js_obf_len"], errors="coerce").fillna(0) if "js_obf_len" in df.columns else 0

    risk = (
        (url_len.clip(0, 200) / 200) * 35 +
        (spec.clip(0, 20) / 20) * 25 +
        (js_len.clip(0, 2000) / 2000) * 20 +
        (js_obf.clip(0, 1000) / 1000) * 20
    ).round().astype(int).clip(0, 100)

    bins = [0, 20, 40, 60, 80, 100]
    labels = ["0–20", "21–40", "41–60", "61–80", "81–100"]
    cat = pd.cut(risk, bins=bins, labels=labels, include_lowest=True)
    counts = cat.value_counts().reindex(labels, fill_value=0)

    return jsonify({"labels": labels, "values": counts.tolist()})


# ---------------- SUSPICIOUS URL TABLE with search/sort/pagination ----------------
@app.route("/urls")
@login_required
def urls():
    """
    Query params:
      q        - search string to match URL (case-insensitive substring)
      filter   - 'bad' or 'good' to filter by prediction
      sort     - column name to sort (e.g., 'ts', 'prediction', 'url')
      order    - 'asc' or 'desc'
      page     - page number (1-indexed)
      per_page - rows per page (default 25)
    """
    q = request.args.get('q', default="", type=str).strip()
    filter_by = request.args.get('filter', default="", type=str).strip()  # 'bad' / 'good'
    sort = request.args.get('sort', default="ts", type=str)
    order = request.args.get('order', default="desc", type=str)
    page = request.args.get('page', default=1, type=int)
    per_page = request.args.get('per_page', default=25, type=int)

    df = df_main.copy()

    # Search
    if q:
        df = df[df['url'].astype(str).str.contains(q, case=False, na=False)]

    # Filter
    if filter_by in ('bad', 'good'):
        df = df[df['prediction'] == filter_by]

    # Sort
    if sort not in df.columns:
        sort = 'ts' if 'ts' in df.columns else df.columns[0]
    ascending = (order == 'asc')
    df = df.sort_values(by=sort, ascending=ascending, na_position='last')

    # Pagination
    total_rows = df.shape[0]
    start = (page - 1) * per_page
    end = start + per_page
    page_df = df.iloc[start:end]

    # Prepare table HTML
    table_html = page_df.to_html(classes='table table-hover align-middle mb-0', index=False, escape=False)

    # Build pagination meta
    total_pages = (total_rows + per_page - 1) // per_page

    return render_template("suspicious.html",
                           table_html=table_html,
                           q=q,
                           filter_by=filter_by,
                           sort=sort,
                           order=order,
                           page=page,
                           per_page=per_page,
                           total_rows=total_rows,
                           total_pages=total_pages)

# ---------------- ADMIN PANEL ----------------
@app.route("/admin")
@login_required
@admin_required
def admin_panel():
    return render_template(
        "admin.html",
        total=len(df_main),
        malicious=len(df_main[df_main["prediction"] == "bad"]),
        benign=len(df_main[df_main["prediction"] == "good"])
    )

#-----------------------View audit---------
@app.route("/admin/audit")
@login_required
@admin_required
def audit_view():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("""
        SELECT ts, username, role, action, endpoint, ip, details
        FROM audit_log
        ORDER BY id DESC
        LIMIT 200
    """)
    rows = cur.fetchall()
    conn.close()

    return render_template("audit.html", rows=rows)

# ---------------- DOWNLOAD filtered CSV ----------------
@app.route("/download_filtered")
@login_required
def download_filtered():
    q = request.args.get('q', default="", type=str).strip()
    filter_by = request.args.get('filter', default="", type=str).strip()
    sort = request.args.get('sort', default="ts", type=str)
    order = request.args.get('order', default="desc", type=str)

    df = df_main.copy()
    if q:
        df = df[df['url'].astype(str).str.contains(q, case=False, na=False)]
    if filter_by in ('bad', 'good'):
        df = df[df['prediction'] == filter_by]
    ascending = (order == 'asc')
    if sort in df.columns:
        df = df.sort_values(by=sort, ascending=ascending, na_position='last')

    # Create CSV in memory
    buf = io.StringIO()
    df.to_csv(buf, index=False)
    buf.seek(0)
    return send_file(io.BytesIO(buf.getvalue().encode('utf-8')),
                     mimetype='text/csv',
                     as_attachment=True,
                     download_name='filtered_results.csv')


# ---------------- SINGLE URL PREDICTION ----------------
@app.route("/predict", methods=["POST"])
def predict():
    url = request.form.get("url", "").strip()
    if not url:
        return redirect("/")

    # Feature extraction (keep consistent with training as much as possible)
    url_length = len(url)
    count_special = sum([1 for ch in url if ch in ['?', '=', '&', '%', '/', ';', '<', '>', '"', "'"]])

    # Match your model expected feature count/order (as you used earlier)
    X = np.array([[url_length, count_special, url_length, 0, 0]])

    prob_mal = get_malicious_probability(model, X)
    risk_score = int(round(prob_mal * 100))

    threshold = get_threshold()
    label = "bad" if prob_mal >= threshold else "good"

    reasons = explain_url(url)
    # Email alert only if malicious AND high risk
    if label == "bad" and risk_score >= 45:
           send_alert_email(url, prob_mal, risk_score, reasons);
    return render_template(
        "index.html",
        title="IDS Dashboard",
        input_url=url,
        result=("Malicious" if label == "bad" else "Benign"),
        prob=f"{prob_mal:.4f}",
        risk_score=risk_score,
        threshold=f"{threshold:.2f}",
        reasons=reasons
    )
    


# ---------------- API ----------------
@app.route("/api/check", methods=["GET"])
def api_check():
    url = request.args.get("url")
    if not url:
        return jsonify({"error": "url param missing"}), 400
    url_length = len(url)
    count_special = sum([1 for ch in url if ch in ['?', '=', '&', '%', '/', ';', '<', '>', '"', "'"]])
    features = np.array([[url_length, count_special, url_length, 0, 0]])
    pred = model.predict(features)[0]
    label = 'bad' if str(pred) in ['1', 'bad', 'malicious'] else 'good'
    return jsonify({"url": url, "prediction": label})

@app.route("/report")
@login_required
def report():
    df = df_main
    mal = int(df[df["prediction"]=="bad"].shape[0])
    ben = int(df[df["prediction"]=="good"].shape[0])
    total = mal + ben

    buffer = io.BytesIO()
    c = canvas.Canvas(buffer, pagesize=letter)
    c.drawString(50, 750, "Cyber Threat Detection Report")
    c.drawString(50, 730, f"Total URLs processed: {total}")
    c.drawString(50, 710, f"Malicious URLs: {mal}")
    c.drawString(50, 690, f"Benign URLs: {ben}")
    c.drawString(50, 670, "Generated by ML-based Web Threat Detection System")
    c.save()
    buffer.seek(0)
    return send_file(buffer, as_attachment=True, download_name="Threat_Report.pdf")

@app.route("/admin/threshold", methods=["GET", "POST"])
def admin_threshold():
    if request.method == "POST":
        new_t = float(request.form.get("threshold", "0.50"))
        set_threshold(new_t)
        return redirect("/admin/threshold")

    current_t = get_threshold()
    return render_template("threshold.html", title="Threshold Settings", threshold=f"{current_t:.2f}")

@app.route("/trenddata")
def trenddata():
    df = df_main.copy()

    # Check timestamp column, if missing create synthetic timeline
    if 'ts' in df.columns:
        df['ts'] = pd.to_datetime(df['ts'], errors='coerce')
        grouped = df.groupby(df['ts'].dt.date)['prediction'].apply(lambda x: (x == 'bad').sum())
    else:
        # Simulated day grouping since Kaggle set may not have timestamps
        df['day'] = (df.index // 5000)  # group every 5000 rows
        grouped = df.groupby('day')['prediction'].apply(lambda x: (x == 'bad').sum())

    labels = grouped.index.astype(str).tolist()
    values = grouped.values.tolist()

    return jsonify({"labels": labels, "values": values})


# ---------------- RUN ----------------
if __name__ == "__main__":
    app.run(debug=True)
