import pytest
from app import app, db, User, Report, FileScan



@pytest.fixture
def client():
    """Create a test client for the Flask app."""
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    app.config['WTF_CSRF_ENABLED'] = False
    app.secret_key = 'test-secret-key'

    with app.app_context():
        db.create_all()
        from app import seed_admin
        seed_admin()
        yield app.test_client()
        db.drop_all()


# ─────────────────────────────────────────
# ROUTE TESTS
# ─────────────────────────────────────────

def test_homepage_loads(client):
    """Home page should return 200."""
    response = client.get('/')
    assert response.status_code == 200


def test_login_page_loads(client):
    """Login page should return 200."""
    response = client.get('/login')
    assert response.status_code == 200


def test_register_page_loads(client):
    """Register page should return 200."""
    response = client.get('/register')
    assert response.status_code == 200


def test_dashboard_redirects_when_not_logged_in(client):
    """Dashboard should redirect to login if not authenticated."""
    response = client.get('/dashboard')
    assert response.status_code == 302
    assert '/login' in response.headers['Location']


def test_report_redirects_when_not_logged_in(client):
    """Report page should redirect to login if not authenticated."""
    response = client.get('/report')
    assert response.status_code == 302
    assert '/login' in response.headers['Location']


def test_verify_otp_redirects_when_no_session(client):
    """OTP page should redirect to login if no OTP in session."""
    response = client.get('/verify-otp')
    assert response.status_code == 302
    assert '/login' in response.headers['Location']


# ─────────────────────────────────────────
# AUTH TESTS
# ─────────────────────────────────────────

def test_register_new_user(client):
    """Registering a new user should redirect to login."""
    response = client.post('/register', data={
        'username': 'testuser',
        'password': 'TestPass123'
    }, follow_redirects=False)
    assert response.status_code == 302
    assert '/login' in response.headers['Location']


def test_register_duplicate_user(client):
    """Registering a duplicate user should redirect back to register."""
    client.post('/register', data={
        'username': 'testuser',
        'password': 'TestPass123'
    })
    response = client.post('/register', data={
        'username': 'testuser',
        'password': 'AnotherPass456'
    }, follow_redirects=False)
    assert response.status_code == 302
    assert '/register' in response.headers['Location']


def test_login_invalid_credentials(client):
    """Login with wrong credentials should stay on login page."""
    response = client.post('/login', data={
        'username': 'nonexistent',
        'password': 'wrongpassword'
    })
    assert response.status_code == 200


def test_logout_redirects(client):
    """Logout should redirect to home."""
    response = client.get('/logout', follow_redirects=False)
    assert response.status_code == 302
    assert '/' in response.headers['Location']


# ─────────────────────────────────────────
# RBAC TESTS
# ─────────────────────────────────────────

def test_default_admin_seeded(client):
    """Admin user should be seeded automatically on startup."""
    with app.app_context():
        admin = User.query.filter_by(username='admin').first()
        assert admin is not None
        assert admin.role == 'Admin'


def test_registration_defaults_to_user(client):
    """Registering a new user should default their role to 'User'."""
    client.post('/register', data={
        'username': 'normal_user',
        'password': 'Password123'
    })
    with app.app_context():
        user = User.query.filter_by(username='normal_user').first()
        assert user is not None
        assert user.role == 'User'


def test_user_cannot_access_admin_or_analyst(client):
    """A standard User should not be allowed to access admin or analyst panels."""
    # Register and mock login as a User
    client.post('/register', data={
        'username': 'normal_user2',
        'password': 'Password123'
    })
    with app.app_context():
        user = User.query.filter_by(username='normal_user2').first()
        user_id = user.id
        
    with client.session_transaction() as sess:
        sess['user_id'] = user_id
        sess['role'] = 'User'

    # Try admin
    response = client.get('/admin')
    assert response.status_code == 302  # redirects with flash
    
    # Try analyst
    response = client.get('/analyst')
    assert response.status_code == 302  # redirects with flash


def test_analyst_cannot_access_admin_or_user_dashboard(client):
    """An Analyst should access analyst routes but not admin or standard user dashboard."""
    # Register and mock login as an Analyst
    client.post('/register', data={
        'username': 'analyst_user',
        'password': 'Password123'
    })
    with app.app_context():
        user = User.query.filter_by(username='analyst_user').first()
        user.role = 'Analyst'
        db.session.commit()
        user_id = user.id

    with client.session_transaction() as sess:
        sess['user_id'] = user_id
        sess['role'] = 'Analyst'

    # Access analyst panel
    response = client.get('/analyst')
    assert response.status_code == 200

    # Try admin panel
    response = client.get('/admin')
    assert response.status_code == 302

    # Try user dashboard
    response = client.get('/dashboard')
    assert response.status_code == 302


def test_admin_cannot_access_user_dashboard(client):
    """An Admin should access admin routes but get redirected from standard user dashboard."""
    with app.app_context():
        admin = User.query.filter_by(username='admin').first()
        admin_id = admin.id

    with client.session_transaction() as sess:
        sess['user_id'] = admin_id
        sess['role'] = 'Admin'

    # Access admin panel
    response = client.get('/admin')
    assert response.status_code == 200

    # Try user dashboard
    response = client.get('/dashboard')
    assert response.status_code == 302


def test_ist_timestamp_format():
    """Verify format_ist converts UTC datetimes to IST with correct string format."""
    from app import format_ist
    from datetime import datetime
    
    # 09:02:31 UTC corresponds to 14:32:31 IST (02:32:31 PM IST)
    dt_utc = datetime(2026, 8, 4, 9, 2, 31)
    formatted = format_ist(dt_utc)
    assert formatted == "04-08-2026 02:32:31 PM IST"


def test_threat_score_calculation():
    """Verify threat intelligence score logic according to security risk rules."""
    from app import calculate_user_threat_score, FileScan, Report

    # 1. Empty scans & reports -> score is 0
    score, level = calculate_user_threat_score([], [])
    assert score == 0
    assert level == "Low"

    # 2. Safe file scan (Low Risk) -> +0 score
    safe_scan = FileScan(filename="clean.txt", risk_level="Low", result="File safe.")
    score, level = calculate_user_threat_score([safe_scan], [])
    assert score == 0

    # 3. Medium & High Risk scans -> +10 and +20
    med_scan = FileScan(filename="script.py", risk_level="Medium", result="Suspicious keyword")
    high_scan = FileScan(filename="virus.exe", risk_level="High", result="Executable detected")
    score, _ = calculate_user_threat_score([med_scan], [])
    assert score == 10
    score, _ = calculate_user_threat_score([high_scan], [])
    assert score == 20
    score, _ = calculate_user_threat_score([safe_scan, med_scan, high_scan], [])
    assert score == 30

    # 4. Incident reports severity: Low (+5), Medium (+10), High (+20)
    low_report = Report(title="Minor Glitch", description="General issue report")
    med_report = Report(title="Suspicious Email", description="Medium risk phishing attempt warning")
    high_report = Report(title="Critical Breach", description="High severity ransomware attack")

    score, _ = calculate_user_threat_score([], [low_report])
    assert score == 5
    score, _ = calculate_user_threat_score([], [med_report])
    assert score == 10
    score, _ = calculate_user_threat_score([], [high_report])
    assert score == 20

    # 5. Combined & clamping between 0 and 100
    score, level = calculate_user_threat_score([high_scan, med_scan], [high_report, med_report, low_report])
    assert score == 65
    assert level == "High"

    # Clamping test (> 100 -> 100)
    many_scans = [high_scan] * 10
    score, _ = calculate_user_threat_score(many_scans, [])
    assert score == 100



