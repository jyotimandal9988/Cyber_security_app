from flask import Flask, render_template, request, redirect, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import os
import random
from datetime import datetime

app = Flask(__name__)
app.secret_key = "supersecretkey"

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
UPLOAD_FOLDER = "static/uploads"

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

db = SQLAlchemy(app)

# ================= MODELS ================= #

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(200))

class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200))
    description = db.Column(db.Text)
    user_id = db.Column(db.Integer)

class FileScan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(200))
    risk_level = db.Column(db.String(50))
    result = db.Column(db.Text)
    user_id = db.Column(db.Integer)

class LoginActivity(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100))
    ip_address = db.Column(db.String(100))
    login_time = db.Column(db.DateTime, default=datetime.utcnow)

with app.app_context():
    db.create_all()

# ================= ROUTES ================= #

@app.route('/')
def index():
    return render_template('index.html')

# -------- REGISTER --------
@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = generate_password_hash(request.form['password'])

        if User.query.filter_by(username=username).first():
            flash("Username already exists!")
            return redirect('/register')

        new_user = User(username=username, password=password)
        db.session.add(new_user)
        db.session.commit()

        flash("Registration Successful! Please Login.")
        return redirect('/login')

    return render_template('register.html')

# -------- LOGIN WITH OTP --------
@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):

            otp = random.randint(100000, 999999)
            session['otp'] = str(otp)
            session['temp_user'] = user.id

            print(f"🔐 OTP for {username}: {otp}")

            flash("OTP sent! Check terminal.")
            return redirect('/verify-otp')
        else:
            flash("Invalid Credentials")

    return render_template('login.html')

# -------- VERIFY OTP --------
@app.route('/verify-otp', methods=['GET','POST'])
def verify_otp():
    if 'otp' not in session:
        return redirect('/login')

    if request.method == 'POST':
        entered_otp = request.form['otp']

        if entered_otp == session.get('otp'):

            user_id = session.pop('temp_user')
            session.pop('otp')

            session['user_id'] = user_id

            # Log login activity
            user = User.query.get(user_id)
            activity = LoginActivity(
                username=user.username,
                ip_address=request.remote_addr
            )
            db.session.add(activity)
            db.session.commit()

            flash("Login Successful with 2FA!")
            return redirect('/dashboard')
        else:
            flash("Invalid OTP")

    return render_template('verify_otp.html')

# -------- DASHBOARD --------
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect('/login')

    reports = Report.query.filter_by(user_id=session['user_id']).all()
    scans = FileScan.query.filter_by(user_id=session['user_id']).all()
    recent_logins = LoginActivity.query.order_by(LoginActivity.login_time.desc()).limit(5).all()

    # Threat Score Calculation
    high_count = sum(1 for s in scans if s.risk_level == "High")
    medium_count = sum(1 for s in scans if s.risk_level == "Medium")

    threat_score = (high_count * 3) + (medium_count * 2) + len(reports)

    if threat_score >= 10:
        threat_level = "High"
    elif threat_score >= 5:
        threat_level = "Moderate"
    else:
        threat_level = "Low"

    return render_template(
        'dashboard.html',
        reports=reports,
        scans=scans,
        threat_score=threat_score,
        threat_level=threat_level,
        recent_logins=recent_logins
    )

# -------- REPORT --------
@app.route('/report', methods=['GET','POST'])
def report():
    if 'user_id' not in session:
        return redirect('/login')

    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']

        new_report = Report(title=title, description=description, user_id=session['user_id'])
        db.session.add(new_report)
        db.session.commit()

        flash("Incident Report Submitted!")
        return redirect('/dashboard')

    return render_template('report.html')

# -------- FILE SCAN --------
@app.route('/scan', methods=['POST'])
def scan():
    if 'user_id' not in session:
        return redirect('/login')

    file = request.files['file']

    if file:
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        file.save(filepath)

        risk_level = "Low"
        result = "File appears safe."

        dangerous_extensions = ['.exe', '.bat', '.cmd', '.sh']
        suspicious_keywords = ['malware', 'virus', 'trojan', 'hack', 'ransom']

        if any(file.filename.lower().endswith(ext) for ext in dangerous_extensions):
            risk_level = "High"
            result = "⚠ Dangerous executable file detected."

        try:
            with open(filepath, 'r', errors='ignore') as f:
                content = f.read().lower()
                if any(word in content for word in suspicious_keywords):
                    risk_level = "Medium"
                    result = "⚠ Suspicious keywords found."
        except:
            pass

        scan_record = FileScan(
            filename=file.filename,
            risk_level=risk_level,
            result=result,
            user_id=session['user_id']
        )

        db.session.add(scan_record)
        db.session.commit()

        flash("File scanned successfully!")

    return redirect('/dashboard')

# -------- LOGOUT --------
@app.route('/logout')
def logout():
    session.clear()
    flash("Logged Out Successfully")
    return redirect('/')

if __name__ == "__main__":
    app.run()