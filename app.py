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


class SecurityEvent(db.Model):

    id = db.Column(db.Integer, primary_key=True)

    event_type = db.Column(db.String(120))
    user = db.Column(db.String(80))

    ip = db.Column(db.String(50))
    severity = db.Column(db.String(20))

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

        file = request.files["file"]

        risk = "LOW"

        if file.filename.lower().endswith((".exe", ".js")):
            risk = "HIGH"


        gcs_path = f"user_{current_user.id}/{file.filename}"

        blob = bucket.blob(gcs_path)
        blob.upload_from_file(file.stream)


        db.session.add(File(
            filename=file.filename,
            owner_id=current_user.id,
            risk=risk
        ))

        db.session.commit()


    files = File.query.filter_by(owner_id=current_user.id).all()

    return render_template("drive.html", files=files)


# ================= DASHBOARD (FIXED) ================= #

@app.route("/dashboard")
@login_required
def dashboard():

    # Only admin allowed
    if current_user.username != "admin":
        return redirect("/drive")


    base = SecurityEvent.query


    events = base.order_by(
        SecurityEvent.timestamp.desc()
    ).limit(30).all()


    counts = {
        "CRITICAL": base.filter_by(severity="CRITICAL").count(),
        "HIGH": base.filter_by(severity="HIGH").count(),
        "MEDIUM": base.filter_by(severity="MEDIUM").count(),
        "LOW": base.filter_by(severity="LOW").count(),
    }


    chart = db.session.query(
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
        chart_values=values
    )


# ================= LOGOUT ================= #

@app.route("/logout")
@login_required
def logout():

    logout_user()

    return redirect(url_for("login_page"))


# ================= INIT ================= #

with app.app_context():

    db.create_all()


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
