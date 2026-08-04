from flask import Flask, render_template, request, redirect, session, flash, abort
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import os
import random
from datetime import datetime, timezone, timedelta
from functools import wraps

app = Flask(__name__)
app.secret_key = "supersecretkey"

IST = timezone(timedelta(hours=5, minutes=30))

def format_ist(dt):
    if not dt:
        return "N/A"
    if isinstance(dt, str):
        return dt
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    ist_dt = dt.astimezone(IST)
    return ist_dt.strftime("%d-%m-%Y %I:%M:%S %p IST")

def to_ist(dt):
    if not dt:
        return None
    if isinstance(dt, str):
        return dt
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(IST)

app.jinja_env.filters['format_ist'] = format_ist

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
    role = db.Column(db.String(20), default="User")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200))
    description = db.Column(db.Text)
    user_id = db.Column(db.Integer)
    status = db.Column(db.String(20), default="Open")
    notes = db.Column(db.Text, default="")


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


# ================= ROLE DECORATOR ================= #

def role_required(*roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                flash("Authentication required. Please login.", "danger")
                return redirect('/login')
            
            user_role = session.get('role')
            if user_role not in roles:
                flash("Access Denied: Permission Required.", "danger")
                if user_role == 'Admin':
                    return redirect('/admin')
                elif user_role == 'Analyst':
                    return redirect('/analyst')
                else:
                    return redirect('/dashboard')
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def seed_admin():
    admin_user = User.query.filter_by(username='admin').first()
    if not admin_user:
        hashed_password = generate_password_hash("Admin@123")
        admin_user = User(username='admin', password=hashed_password, role='Admin')
        db.session.add(admin_user)
        db.session.commit()


with app.app_context():
    db.create_all()
    
    # Database migration: check if columns exist in sqlite and alter table if not
    from sqlalchemy import inspect
    inspector = inspect(db.engine)
    
    # Check 'user' table columns
    user_columns = [c['name'] for c in inspector.get_columns('user')]
    if 'role' not in user_columns:
        db.session.execute(db.text("ALTER TABLE user ADD COLUMN role VARCHAR(20) DEFAULT 'User'"))
        db.session.commit()
    if 'created_at' not in user_columns:
        db.session.execute(db.text("ALTER TABLE user ADD COLUMN created_at DATETIME"))
        db.session.execute(db.text("UPDATE user SET created_at = CURRENT_TIMESTAMP WHERE created_at IS NULL"))
        db.session.commit()
        
    # Check 'report' table columns
    report_columns = [c['name'] for c in inspector.get_columns('report')]
    if 'status' not in report_columns:
        db.session.execute(db.text("ALTER TABLE report ADD COLUMN status VARCHAR(20) DEFAULT 'Open'"))
        db.session.commit()
    if 'notes' not in report_columns:
        db.session.execute(db.text("ALTER TABLE report ADD COLUMN notes TEXT DEFAULT ''"))
        db.session.commit()

    # Seed default admin account
    seed_admin()


# ================= ROUTES ================= #

@app.route('/')
def index():
    return render_template('index.html')


# -------- REGISTER --------
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = generate_password_hash(request.form['password'])

        if User.query.filter_by(username=username).first():
            flash("Username already exists!")
            return redirect('/register')

        # Normal users automatically get "User" role
        new_user = User(username=username, password=password, role='User')
        db.session.add(new_user)
        db.session.commit()

        flash("Registration Successful! Please Login.")
        return redirect('/login')

    return render_template('register.html')


# -------- LOGIN WITH OTP --------
@app.route('/login', methods=['GET', 'POST'])
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
@app.route('/verify-otp', methods=['GET', 'POST'])
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
            session['role'] = user.role
            
            activity = LoginActivity(
                username=user.username,
                ip_address=request.remote_addr
            )
            db.session.add(activity)
            db.session.commit()

            flash("Login Successful with 2FA!")
            
            if user.role == 'Admin':
                return redirect('/admin')
            elif user.role == 'Analyst':
                return redirect('/analyst')
            else:
                return redirect('/dashboard')
        else:
            flash("Invalid OTP")

    return render_template('verify_otp.html')


def calculate_user_threat_score(scans, reports):
    score = 0

    # File scans scoring: Low (+0), Medium (+10), High (+20)
    for s in scans:
        if s.risk_level == "High":
            score += 20
        elif s.risk_level == "Medium":
            score += 10
        # Low Risk file: +0

    # Incident reports scoring based on severity: Low (+5), Medium (+10), High (+20)
    for r in reports:
        text = (getattr(r, 'title', '') or '').lower() + ' ' + (getattr(r, 'description', '') or '').lower()
        if any(keyword in text for keyword in ['high', 'critical', 'severe', 'breach', 'ransomware', 'attack']):
            score += 20
        elif any(keyword in text for keyword in ['medium', 'moderate', 'suspicious', 'phishing', 'warning', 'leak']):
            score += 10
        else:
            # Default / Low severity incident report: +5
            score += 5

    # Ensure score stays strictly between 0 and 100
    clamped_score = max(0, min(100, score))

    if clamped_score >= 40:
        threat_level = "High"
    elif clamped_score >= 15:
        threat_level = "Moderate"
    else:
        threat_level = "Low"

    return clamped_score, threat_level


# -------- DASHBOARD --------
@app.route('/dashboard')
@role_required('User')
def dashboard():
    user = User.query.get(session['user_id'])
    reports = Report.query.filter_by(user_id=session['user_id']).all()
    scans = FileScan.query.filter_by(user_id=session['user_id']).all()
    recent_logins = LoginActivity.query.filter_by(username=user.username).order_by(LoginActivity.login_time.desc()).limit(5).all()

    # Threat Score Calculation
    threat_score, threat_level = calculate_user_threat_score(scans, reports)

    return render_template(
        'dashboard.html',
        reports=reports,
        scans=scans,
        threat_score=threat_score,
        threat_level=threat_level,
        recent_logins=recent_logins
    )


# -------- REPORT --------
@app.route('/report', methods=['GET', 'POST'])
@role_required('User')
def report():
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
@role_required('User')
def scan():
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
        except Exception:
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


# -------- ADMIN PANEL --------
def get_admin_data():
    users = User.query.all()
    reports = Report.query.all()
    scans = FileScan.query.all()
    login_activities = LoginActivity.query.order_by(LoginActivity.login_time.desc()).all()
    
    total_users = len(users)
    total_reports = len(reports)
    total_scans = len(scans)
    high_risk_files = sum(1 for s in scans if s.risk_level == "High")
    
    today = datetime.now(IST).date()
    todays_logins = sum(1 for log in login_activities if log.login_time and to_ist(log.login_time).date() == today)
    
    user_scores = []
    for u in users:
        u_scans = [s for s in scans if s.user_id == u.id]
        u_reports = [r for r in reports if r.user_id == u.id]
        score, _ = calculate_user_threat_score(u_scans, u_reports)
        user_scores.append(score)
        
    avg_threat_score = round(sum(user_scores) / len(user_scores), 2) if user_scores else 0.0
    
    users_map = {u.id: u.username for u in users}

    return {
        'users': users,
        'reports': reports,
        'scans': scans,
        'login_activities': login_activities,
        'total_users': total_users,
        'total_reports': total_reports,
        'total_scans': total_scans,
        'high_risk_files': high_risk_files,
        'todays_logins': todays_logins,
        'avg_threat_score': avg_threat_score,
        'users_map': users_map
    }


@app.route('/admin')
@role_required('Admin')
def admin_panel():
    data = get_admin_data()
    return render_template('admin.html', **data)


@app.route('/manage-users')
@role_required('Admin')
def manage_users():
    data = get_admin_data()
    return render_template('admin.html', scroll_to='users-section', **data)


@app.route('/change-role/<int:user_id>', methods=['POST'])
@role_required('Admin')
def change_role(user_id):
    user = User.query.get_or_404(user_id)
    if user.username == 'admin':
        flash("Cannot change role of default Admin user.", "danger")
        return redirect('/admin')
    
    new_role = request.form.get('role')
    if new_role in ['Admin', 'Analyst', 'User']:
        user.role = new_role
        db.session.commit()
        flash("Role Updated Successfully", "success")
    else:
        flash("Invalid role selected.", "danger")
    return redirect('/admin')


@app.route('/delete-user/<int:user_id>', methods=['POST'])
@role_required('Admin')
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    if user.username == 'admin':
        flash("Cannot delete default Admin user.", "danger")
        return redirect('/admin')
    
    # Clean up user files and reports
    Report.query.filter_by(user_id=user.id).delete()
    FileScan.query.filter_by(user_id=user.id).delete()
    
    db.session.delete(user)
    db.session.commit()
    flash("User Deleted", "success")
    return redirect('/admin')


@app.route('/delete-report/<int:report_id>', methods=['POST'])
@role_required('Admin')
def delete_report(report_id):
    report = Report.query.get_or_404(report_id)
    db.session.delete(report)
    db.session.commit()
    flash("Report Deleted Successfully", "success")
    return redirect('/admin')


# -------- ANALYST PANEL --------
@app.route('/analyst')
@role_required('Analyst')
def analyst_panel():
    reports = Report.query.all()
    scans = FileScan.query.all()
    users_map = {u.id: u.username for u in User.query.all()}
    return render_template(
        'analyst.html',
        reports=reports,
        scans=scans,
        users_map=users_map
    )


@app.route('/update-report-status/<int:report_id>', methods=['POST'])
@role_required('Analyst')
def update_report_status(report_id):
    report = Report.query.get_or_404(report_id)
    status = request.form.get('status')
    notes = request.form.get('notes', '')
    
    if status in ['Open', 'Investigating', 'Resolved', 'Closed']:
        report.status = status
        report.notes = notes
        db.session.commit()
        flash("Report updated successfully", "success")
    else:
        flash("Invalid status", "danger")
    return redirect('/analyst')


# -------- LOGOUT --------
@app.route('/logout')
def logout():
    session.clear()
    flash("Logged Out Successfully")
    return redirect('/')


if __name__ == "__main__":
    app.run()
