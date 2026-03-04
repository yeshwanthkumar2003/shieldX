from flask import Flask, render_template, request, redirect, jsonify, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, UserMixin,
    login_user, login_required,
    logout_user, current_user
)

from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from collections import defaultdict
from sqlalchemy import func

import uuid
import smtplib
import ssl
import os

# ================= ENV ================= #

from dotenv import load_dotenv
load_dotenv()

# ================= GCP ================= #

from google.cloud import storage
from google.oauth2 import service_account

# ================= FIREBASE ================= #

import firebase_admin
from firebase_admin import credentials, auth


# ================= APP ================= #

app = Flask(__name__)

app.secret_key = os.getenv("SECRET_KEY", "shieldx-secret-key")

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///shieldx.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)


# ================= LOGIN ================= #

login_manager = LoginManager(app)
login_manager.login_view = "login_page"


# ================= FIREWALL ================= #

FAILED_LOGINS = defaultdict(int)
BLOCKED_IPS = {}


# ================= GCS ================= #

SERVICE_ACCOUNT_FILE = "creds.json"
BUCKET_NAME = "shieldx"

gcp_credentials = service_account.Credentials.from_service_account_file(
    SERVICE_ACCOUNT_FILE
)

gcs_client = storage.Client(
    project=gcp_credentials.project_id,
    credentials=gcp_credentials
)

bucket = gcs_client.bucket(BUCKET_NAME)


# ================= FIREBASE ================= #

if not firebase_admin._apps:
    cred = credentials.Certificate("firebase-admin.json")
    firebase_admin.initialize_app(cred)


# ================= EMAIL ================= #

EMAIL = os.getenv("EMAIL_USER")
EMAIL_PASS = os.getenv("EMAIL_PASS")

print("Loaded Email:", EMAIL)


# ================= MODELS ================= #

class User(db.Model, UserMixin):

    id = db.Column(db.Integer, primary_key=True)

    username = db.Column(db.String(80), unique=True)
    email = db.Column(db.String(120), unique=True)

    password = db.Column(db.String(200))

    provider = db.Column(db.String(20), default="local")

    verified = db.Column(db.Boolean, default=False)
    verify_token = db.Column(db.String(120))


class File(db.Model):

    id = db.Column(db.Integer, primary_key=True)

    filename = db.Column(db.String(200))
    owner_id = db.Column(db.Integer)

    risk = db.Column(db.String(20), default="LOW")
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)

    trashed = db.Column(db.Boolean, default=False)
    trashed_at = db.Column(db.DateTime, nullable=True)


class SecurityEvent(db.Model):

    id = db.Column(db.Integer, primary_key=True)

    event_type = db.Column(db.String(120))
    user = db.Column(db.String(80))

    ip = db.Column(db.String(50))
    severity = db.Column(db.String(20))

    timestamp = db.Column(db.DateTime, default=datetime.utcnow)


class Feedback(db.Model):

    id = db.Column(db.Integer, primary_key=True)

    user = db.Column(db.String(80))
    rating = db.Column(db.Integer)
    message = db.Column(db.Text)

    timestamp = db.Column(db.DateTime, default=datetime.utcnow)


# ================= LOGIN MANAGER ================= #

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


# ================= EMAIL FUNCTION ================= #

def send_verification(email, token):

    if not EMAIL or not EMAIL_PASS:
        print("❌ Email credentials missing")
        return False


    link = f"http://127.0.0.1:5000/verify/{token}"

    subject = "ShieldX Email Verification"

    body = f"""
Hello,

Please verify your ShieldX account:

{link}

Regards,
ShieldX Team
"""

    message = f"Subject: {subject}\n\n{body}"

    context = ssl.create_default_context()

    try:

        with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=context) as server:

            server.login(EMAIL, EMAIL_PASS)
            server.sendmail(EMAIL, email, message)

        print("✅ Email sent to:", email)

        return True


    except Exception as e:

        print("❌ Email error:", e)
        return False


# ================= LOGIN PAGE ================= #

@app.route("/")
def login_page():
    return render_template("login.html")


# ================= SIGNUP PAGE ================= #

@app.route("/signup", methods=["GET"])
def signup_page():
    return render_template("signup.html")


# ================= LOGIN API ================= #

@app.route("/login", methods=["POST"])
def login_api():

    ip = request.remote_addr

    if ip in BLOCKED_IPS and datetime.utcnow() < BLOCKED_IPS[ip]:

        return jsonify({
            "success": False,
            "message": "Too many attempts. Try later"
        }), 403


    data = request.get_json()

    username = data.get("username")
    password = data.get("password")
    remember = data.get("remember", False)


    user = User.query.filter(
        (User.username == username) |
        (User.email == username)
    ).first()


    if not user:

        FAILED_LOGINS[ip] += 1

        return jsonify({
            "success": False,
            "message": "User not found"
        })


    if not user.verified:

        return jsonify({
            "success": False,
            "verified": False,
            "message": "Verify email first"
        })


    if not check_password_hash(user.password, password):

        FAILED_LOGINS[ip] += 1

        if FAILED_LOGINS[ip] >= 5:
            BLOCKED_IPS[ip] = datetime.utcnow() + timedelta(minutes=10)

        return jsonify({
            "success": False,
            "message": "Wrong password"
        })


    FAILED_LOGINS[ip] = 0

    login_user(user, remember=remember)


    return jsonify({
        "success": True,
        "verified": True
    })


# ================= SIGNUP API ================= #

@app.route("/signup", methods=["POST"])
def signup_api():

    data = request.get_json()

    name = data.get("name")
    email = data.get("email")
    password = data.get("password")


    if not name or not email or not password:

        return jsonify({
            "success": False,
            "message": "All fields required"
        })


    if User.query.filter_by(email=email).first():

        return jsonify({
            "success": False,
            "message": "Email already registered"
        })


    token = str(uuid.uuid4())


    user = User(

        username=name,
        email=email,

        password=generate_password_hash(password),

        verify_token=token,
        verified=False

    )

    db.session.add(user)
    db.session.commit()


    mail_sent = send_verification(email, token)


    if not mail_sent:

        return jsonify({
            "success": False,
            "message": "Email sending failed"
        })


    return jsonify({
        "success": True,
        "message": "Verification email sent"
    })


# ================= VERIFY ================= #

@app.route("/verify/<token>")
def verify(token):

    user = User.query.filter_by(verify_token=token).first()

    if not user:
        return "Invalid or expired link"


    user.verified = True
    user.verify_token = None

    db.session.commit()

    return render_template("verify.html")


# ================= GOOGLE LOGIN ================= #

@app.route("/google-login", methods=["POST"])
def google_login():

    data = request.get_json()

    token = data.get("token")

   

    if not token:
        return jsonify({"success": False}), 400


    try:

        decoded = auth.verify_id_token(token)

        email = decoded["email"]
        name = decoded.get("name", email.split("@")[0])


    except Exception as e:

        print("Google Auth Error:", e)

        return jsonify({
            "success": False,
            "message": "Invalid Google token"
        }), 401


    user = User.query.filter_by(email=email).first()


    if not user:

        user = User(

            username=name,
            email=email,

            provider="google",
            verified=True

        )

        db.session.add(user)
        db.session.commit()


    login_user(user)

    return jsonify({"success": True})


# ================= DRIVE ================= #

@app.route("/drive", methods=["GET", "POST"])
@login_required
def drive():

    if request.method == "POST":

        if "file" not in request.files:
            return redirect("/drive")

        file = request.files["file"]

        if file.filename == "":
            return redirect("/drive")

        filename = file.filename

        # 🔍 SECURITY SCAN (Basic)
        risk = "LOW"
        severity = "LOW"

        dangerous_ext = (".exe", ".js", ".bat", ".cmd", ".scr", ".ps1")

        if filename.lower().endswith(dangerous_ext):
            risk = "HIGH"
            severity = "HIGH"

        # 📦 Upload to GCS
        gcs_path = f"user_{current_user.id}/{filename}"

        blob = bucket.blob(gcs_path)

        file.stream.seek(0)
        file_bytes = file.stream.read()
        content_type = file.content_type or "application/octet-stream"
        blob.upload_from_string(file_bytes, content_type=content_type)
        print(f"✅ Uploaded {filename} to GCS at {gcs_path}")

        # 💾 Save file record
        db.session.add(File(
            filename=filename,
            owner_id=current_user.id,
            risk=risk
        ))

        # 🛡️ LOG SECURITY EVENT
        db.session.add(SecurityEvent(
            event_type=f"File uploaded: {filename}",
            user=current_user.username,
            ip=request.remote_addr,
            severity=severity
        ))

        db.session.commit()

        return redirect("/drive")

    # GET request → show files (exclude trashed)
    files = File.query.filter_by(owner_id=current_user.id, trashed=False).order_by(File.uploaded_at.desc()).all()

    activity = SecurityEvent.query.filter_by(
        user=current_user.username
    ).order_by(SecurityEvent.timestamp.desc()).limit(10).all()

    return render_template("drive.html", files=files, activity=activity)
# ================= DASHBOARD (FIXED) ================= #

@app.route("/dashboard")
@login_required
def dashboard():

    # Only admin allowed
    if current_user.username != "admin":
        return redirect("/drive")


    selected_days = request.args.get("days", "30")

    base = SecurityEvent.query

    if selected_days != "all":
        try:
            cutoff = datetime.utcnow() - timedelta(days=int(selected_days))
            base = base.filter(SecurityEvent.timestamp >= cutoff)
        except ValueError:
            pass


    events = base.order_by(
        SecurityEvent.timestamp.desc()
    ).limit(50).all()


    counts = {
        "CRITICAL": base.filter(SecurityEvent.severity == "CRITICAL").count(),
        "HIGH": base.filter(SecurityEvent.severity == "HIGH").count(),
        "MEDIUM": base.filter(SecurityEvent.severity == "MEDIUM").count(),
        "LOW": base.filter(SecurityEvent.severity == "LOW").count(),
    }


    chart = base.with_entities(
        func.date(SecurityEvent.timestamp),
        func.count(SecurityEvent.id)
    ).group_by(func.date(SecurityEvent.timestamp)).all()


    dates = [str(r[0]) for r in chart]
    values = [r[1] for r in chart]


    return render_template(
        "dashboard.html",
        events=events,
        counts=counts,
        chart_dates=dates,
        chart_values=values,
        selected_days=selected_days
    )


# ================= FEEDBACK ================= #

@app.route("/feedback", methods=["POST"])
@login_required
def submit_feedback():

    data = request.get_json()

    rating = data.get("rating", 0)
    message = data.get("message", "").strip()

    if not 1 <= int(rating) <= 5:
        return jsonify({"success": False, "message": "Invalid rating"}), 400

    fb = Feedback(
        user=current_user.username,
        rating=int(rating),
        message=message
    )

    db.session.add(fb)
    db.session.commit()

    return jsonify({"success": True})


# ================= FEEDBACK LIST ================= #

@app.route("/feedbacks")
@login_required
def feedbacks_page():

    all_feedback = Feedback.query.order_by(
        Feedback.timestamp.desc()
    ).all()

    # Calculate average rating
    ratings = [f.rating for f in all_feedback]
    avg_rating = sum(ratings) / len(ratings) if ratings else 0

    return render_template(
        "feedbacks.html",
        feedbacks=all_feedback,
        total=len(all_feedback),
        avg_rating=round(avg_rating, 1)
    )


# ================= RECENT ================= #

@app.route("/recent")
@login_required
def recent():

    files = File.query.filter_by(
        owner_id=current_user.id,
        trashed=False
    ).order_by(File.uploaded_at.desc()).limit(20).all()

    return render_template("recent.html", files=files)


# ================= FILE DOWNLOAD ================= #

@app.route("/file/download/<int:file_id>")
@login_required
def download_file(file_id):

    from flask import send_file
    import io

    f = db.session.get(File, file_id)

    if not f or f.owner_id != current_user.id:
        return "Not found", 404

    gcs_path = f"user_{current_user.id}/{f.filename}"
    blob = bucket.blob(gcs_path)

    try:
        data = blob.download_as_bytes()
    except Exception as e:
        print("GCS download error:", e)
        return "File not found in storage", 404

    return send_file(
        io.BytesIO(data),
        download_name=f.filename,
        as_attachment=True
    )


# ================= MOVE TO TRASH ================= #

@app.route("/file/trash/<int:file_id>", methods=["POST"])
@login_required
def trash_file(file_id):

    f = db.session.get(File, file_id)

    if not f or f.owner_id != current_user.id:
        return "Not found", 404

    f.trashed = True
    f.trashed_at = datetime.utcnow()

    db.session.commit()

    return redirect("/drive")


# ================= TRASH PAGE ================= #

@app.route("/trash")
@login_required
def trash_page():

    items = File.query.filter_by(
        owner_id=current_user.id,
        trashed=True
    ).order_by(File.trashed_at.desc()).all()

    return render_template("trash.html", items=items)


# ================= RESTORE FROM TRASH ================= #

@app.route("/trash/restore/<int:file_id>", methods=["POST"])
@login_required
def restore_file(file_id):

    f = db.session.get(File, file_id)

    if not f or f.owner_id != current_user.id:
        return "Not found", 404

    f.trashed = False
    f.trashed_at = None

    db.session.commit()

    return redirect("/trash")


# ================= PERMANENT DELETE ================= #

@app.route("/trash/delete/<int:file_id>", methods=["POST"])
@login_required
def delete_file(file_id):

    f = db.session.get(File, file_id)

    if not f or f.owner_id != current_user.id:
        return "Not found", 404

    # Delete from GCS
    try:
        gcs_path = f"user_{current_user.id}/{f.filename}"
        blob = bucket.blob(gcs_path)
        blob.delete()
    except Exception as e:
        print("GCS delete error:", e)

    db.session.delete(f)
    db.session.commit()

    return redirect("/trash")


# ================= LOGOUT ================= #

@app.route("/logout")
@login_required
def logout():

    logout_user()

    return redirect(url_for("login_page"))


# ================= INIT ================= #

with app.app_context():

    db.create_all()

    # Migrate: add columns if missing (SQLite doesn't auto-add)
    with db.engine.connect() as _conn:
        for _tbl, _col, _def in [
            ("file", "trashed", "BOOLEAN DEFAULT 0"),
            ("file", "trashed_at", "DATETIME"),
        ]:
            try:
                _conn.execute(db.text(f"ALTER TABLE {_tbl} ADD COLUMN {_col} {_def}"))
                _conn.commit()
            except Exception:
                pass


    if not User.query.filter_by(username="admin").first():

        admin = User(

            username="admin",
            password=generate_password_hash("admin123"),
            verified=True

        )

        db.session.add(admin)
        db.session.commit()


# ================= RUN ================= #

if __name__ == "__main__":

    app.run(debug=True)
