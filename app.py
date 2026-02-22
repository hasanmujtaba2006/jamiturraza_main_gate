"""
Jamia Gate Management System
Flask + SQLAlchemy + SQLite (Railway ready)
"""

import os
from datetime import datetime, timedelta
from functools import wraps

from dotenv import load_dotenv
from flask import (Flask, render_template, redirect, url_for,
                   request, flash, session, Response, abort)
from flask_login import (LoginManager, UserMixin, login_user,
                         logout_user, login_required, current_user)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import csv
import io

# ── Bootstrap ──────────────────────────────────────────────
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY']         = os.getenv('SECRET_KEY', 'dev-secret-change-in-production')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///gate_system.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=1)

db          = SQLAlchemy(app)
login_mgr   = LoginManager(app)
login_mgr.login_view = 'login'

MAX_ATTEMPTS = 5   # Failed logins before lockout

# ══════════════════════════════════════════════════════════
#  MODELS
# ══════════════════════════════════════════════════════════

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id           = db.Column(db.Integer, primary_key=True)
    user_id      = db.Column(db.String(30), unique=True, nullable=False)
    full_name    = db.Column(db.String(100), nullable=False)
    role         = db.Column(db.String(20), nullable=False)   # super_admin|admin|principal|warden|supervisor|guard|student|staff
    department   = db.Column(db.String(100))
    email        = db.Column(db.String(100))
    phone        = db.Column(db.String(20))
    password     = db.Column(db.String(255), nullable=False)
    status       = db.Column(db.String(10), default='active')  # active|inactive
    deact_reason = db.Column(db.String(255))
    created_by   = db.Column(db.Integer)
    created_at   = db.Column(db.DateTime, default=datetime.utcnow)

    @property
    def initials(self):
        parts = self.full_name.split()
        return (parts[0][0] + (parts[1][0] if len(parts) > 1 else 'X')).upper()

    @property
    def role_label(self):
        labels = {
            'super_admin': 'Super Admin', 'admin': 'Admin',
            'principal': 'Principal',     'warden': 'Warden',
            'supervisor': 'Supervisor',   'guard': 'Guard',
            'student': 'Student',         'staff': 'Staff',
        }
        return labels.get(self.role, self.role.title())

    @property
    def role_level(self):
        levels = {'guard':1,'student':1,'staff':1,'warden':2,
                  'supervisor':2,'principal':3,'admin':4,'super_admin':5}
        return levels.get(self.role, 0)


class EntryLog(db.Model):
    __tablename__ = 'entry_log'
    id         = db.Column(db.Integer, primary_key=True)
    person_id  = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    log_type   = db.Column(db.String(10), nullable=False)  # entry|exit|blocked
    gate       = db.Column(db.String(50), default='Main Gate')
    guard_id   = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    method     = db.Column(db.String(20), default='qr_scan')  # qr_scan|manual|id_card
    notes      = db.Column(db.Text)
    logged_at  = db.Column(db.DateTime, default=datetime.utcnow)

    person = db.relationship('User', foreign_keys=[person_id])
    guard  = db.relationship('User', foreign_keys=[guard_id])


class Alert(db.Model):
    __tablename__ = 'alerts'
    id           = db.Column(db.Integer, primary_key=True)
    type         = db.Column(db.String(10), default='info')  # critical|warning|info
    title        = db.Column(db.String(200), nullable=False)
    description  = db.Column(db.Text)
    related_user = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    related_guard= db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    is_read      = db.Column(db.Boolean, default=False)
    created_at   = db.Column(db.DateTime, default=datetime.utcnow)

    rel_user  = db.relationship('User', foreign_keys=[related_user])
    rel_guard = db.relationship('User', foreign_keys=[related_guard])


class AuditLog(db.Model):
    __tablename__ = 'audit_log'
    id         = db.Column(db.Integer, primary_key=True)
    actor_id   = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    action     = db.Column(db.String(100), nullable=False)
    target_id  = db.Column(db.Integer, nullable=True)
    details    = db.Column(db.Text)
    ip_address = db.Column(db.String(45))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    actor = db.relationship('User', foreign_keys=[actor_id])


class LoginAttempt(db.Model):
    __tablename__ = 'login_attempts'
    id           = db.Column(db.Integer, primary_key=True)
    user_id_str  = db.Column(db.String(30))
    ip_address   = db.Column(db.String(45))
    success      = db.Column(db.Boolean, default=False)
    attempted_at = db.Column(db.DateTime, default=datetime.utcnow)


# ══════════════════════════════════════════════════════════
#  HELPERS
# ══════════════════════════════════════════════════════════

@login_mgr.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


def log_audit(actor_id, action, target_id=None, details=''):
    ip = request.remote_addr or 'unknown'
    entry = AuditLog(actor_id=actor_id, action=action,
                     target_id=target_id, details=details, ip_address=ip)
    db.session.add(entry)
    db.session.commit()


def create_alert(type_, title, desc, rel_user=None, rel_guard=None):
    a = Alert(type=type_, title=title, description=desc,
              related_user=rel_user, related_guard=rel_guard)
    db.session.add(a)
    db.session.commit()


def require_role(min_role):
    """Decorator: blocks access if user's role level is below min_role."""
    def decorator(f):
        @wraps(f)
        @login_required
        def decorated(*args, **kwargs):
            levels = {'guard':1,'student':1,'staff':1,'warden':2,
                      'supervisor':2,'principal':3,'admin':4,'super_admin':5}
            if levels.get(current_user.role, 0) < levels.get(min_role, 99):
                flash('You do not have permission to access this page.', 'error')
                return redirect(url_for('dashboard'))
            return f(*args, **kwargs)
        return decorated
    return decorator


def unread_alert_count():
    return Alert.query.filter_by(is_read=False).count()


# ══════════════════════════════════════════════════════════
#  ROUTES — AUTH
# ══════════════════════════════════════════════════════════

@app.route('/')
@login_required
def dashboard():
    if current_user.role in ('guard', 'student', 'staff'):
        return redirect(url_for('scanner'))

    today = datetime.utcnow().date()
    entries  = EntryLog.query.filter(EntryLog.log_type=='entry',
                  db.func.date(EntryLog.logged_at)==today).count()
    exits    = EntryLog.query.filter(EntryLog.log_type=='exit',
                  db.func.date(EntryLog.logged_at)==today).count()
    blocked  = EntryLog.query.filter(EntryLog.log_type=='blocked',
                  db.func.date(EntryLog.logged_at)==today).count()
    inside   = max(0, entries - exits)
    alerts   = unread_alert_count()
    students = User.query.filter_by(role='student', status='active').count()
    staff    = User.query.filter_by(role='staff',   status='active').count()
    inactive = User.query.filter_by(status='inactive').count()

    recent_logs = (EntryLog.query
                   .order_by(EntryLog.logged_at.desc())
                   .limit(8).all())
    recent_alerts = (Alert.query
                     .order_by(Alert.created_at.desc())
                     .limit(5).all())

    return render_template('dashboard.html',
        entries=entries, exits=exits, blocked=blocked,
        inside=inside, alerts=alerts, students=students,
        staff=staff, inactive=inactive,
        recent_logs=recent_logs, recent_alerts=recent_alerts,
        alert_count=alerts)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        uid      = request.form.get('user_id', '').strip()
        password = request.form.get('password', '').strip()
        ip       = request.remote_addr or 'unknown'

        # Check lockout
        cutoff   = datetime.utcnow() - timedelta(minutes=15)
        attempts = LoginAttempt.query.filter(
            LoginAttempt.user_id_str == uid,
            LoginAttempt.success == False,
            LoginAttempt.attempted_at >= cutoff
        ).count()

        if attempts >= MAX_ATTEMPTS:
            create_alert('critical', 'Account Locked — Multiple Failed Logins',
                         f"User ID: {uid} locked after {attempts} attempts. IP: {ip}")
            flash(f'🔐 Account locked for 15 minutes after {MAX_ATTEMPTS} failed attempts.', 'error')
            return render_template('login.html')

        user = User.query.filter_by(user_id=uid).first()
        valid = user and check_password_hash(user.password, password)

        if valid:
            if user.status == 'inactive':
                db.session.add(LoginAttempt(user_id_str=uid, ip_address=ip, success=False))
                db.session.commit()
                flash(f'🚫 Account deactivated. Reason: {user.deact_reason or "Contact admin"}', 'error')
            else:
                db.session.add(LoginAttempt(user_id_str=uid, ip_address=ip, success=True))
                db.session.commit()
                login_user(user, remember=False)
                session.permanent = True
                log_audit(user.id, 'LOGIN', details=f'Logged in from {ip}')
                flash(f'Welcome back, {user.full_name}!', 'success')
                return redirect(url_for('scanner') if user.role == 'guard'
                                else url_for('dashboard'))
        else:
            db.session.add(LoginAttempt(user_id_str=uid, ip_address=ip, success=False))
            db.session.commit()
            new_count = attempts + 1
            if new_count >= MAX_ATTEMPTS:
                create_alert('critical', 'Multiple Failed Login Attempts',
                             f"User ID: {uid} — {new_count} failed attempts. IP: {ip}")
            flash('❌ Invalid User ID or Password.', 'error')

    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    log_audit(current_user.id, 'LOGOUT')
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))


# ══════════════════════════════════════════════════════════
#  ROUTES — SCANNER
# ══════════════════════════════════════════════════════════

@app.route('/scanner', methods=['GET', 'POST'])
@login_required
def scanner():
    scanned_user = None
    scan_result  = None
    scan_id_val  = ''

    today = datetime.utcnow().date()
    today_e = EntryLog.query.filter(EntryLog.log_type=='entry',
                db.func.date(EntryLog.logged_at)==today).count()
    today_x = EntryLog.query.filter(EntryLog.log_type=='exit',
                db.func.date(EntryLog.logged_at)==today).count()
    today_b = EntryLog.query.filter(EntryLog.log_type=='blocked',
                db.func.date(EntryLog.logged_at)==today).count()

    if request.method == 'POST':
        action = request.form.get('action', '')

        # ── QR/ID Scan ──
        if action in ('check', 'entry', 'exit'):
            scan_id_val = request.form.get('scan_id', '').strip()
            gate        = request.form.get('gate', 'Main Gate')
            scanned_user = User.query.filter_by(user_id=scan_id_val).first()

            if not scanned_user:
                scan_result = 'not_found'
                create_alert('warning', 'Unknown ID Scan Attempt',
                             f"ID '{scan_id_val}' not found. Gate: {gate}. Guard: {current_user.user_id}")

            elif scanned_user.status == 'inactive':
                scan_result = 'blocked'
                log = EntryLog(person_id=scanned_user.id, log_type='blocked',
                               gate=gate, guard_id=current_user.id, method='qr_scan',
                               notes='Inactive account')
                db.session.add(log)
                db.session.commit()
                create_alert('critical', '🚫 Inactive Account Entry Attempt',
                             f"{scanned_user.full_name} – {scanned_user.user_id} attempted "
                             f"entry at {gate}. Reason: {scanned_user.deact_reason or 'Deactivated'}",
                             scanned_user.id, current_user.id)
                log_audit(current_user.id, 'BLOCKED_ENTRY', scanned_user.id,
                          f"Inactive user tried to enter at {gate}")

            elif action in ('entry', 'exit'):
                log = EntryLog(person_id=scanned_user.id, log_type=action,
                               gate=gate, guard_id=current_user.id, method='qr_scan')
                db.session.add(log)
                db.session.commit()
                log_audit(current_user.id, f'{action.upper()}_RECORDED',
                          scanned_user.id, f"Gate: {gate}")
                flash(f'✅ {action.title()} recorded for {scanned_user.full_name}', 'success')
                scanned_user = None
            else:
                scan_result = 'allowed'

        # ── Manual Entry ──
        elif action == 'manual':
            mid    = request.form.get('manual_id', '').strip()
            mtype  = request.form.get('manual_type', 'entry')
            mgate  = request.form.get('manual_gate', 'Main Gate')
            mnotes = request.form.get('manual_notes', '')
            muser  = User.query.filter_by(user_id=mid, status='active').first()
            if muser:
                log = EntryLog(person_id=muser.id, log_type=mtype,
                               gate=mgate, guard_id=current_user.id,
                               method='manual', notes=mnotes)
                db.session.add(log)
                db.session.commit()
                log_audit(current_user.id, f'MANUAL_{mtype.upper()}',
                          muser.id, f"Manual by guard. Gate: {mgate}")
                flash(f'✅ Manual {mtype} recorded for {muser.full_name}', 'success')
            else:
                flash('❌ ID not found or account is inactive.', 'error')

    return render_template('scanner.html',
        scanned_user=scanned_user, scan_result=scan_result,
        scan_id_val=scan_id_val,
        today_e=today_e, today_x=today_x, today_b=today_b,
        inside=max(0, today_e-today_x),
        alert_count=unread_alert_count())


# ══════════════════════════════════════════════════════════
#  ROUTES — ENTRY/EXIT LOG
# ══════════════════════════════════════════════════════════

@app.route('/log')
@login_required
def log():
    type_f   = request.args.get('type',   '')
    gate_f   = request.args.get('gate',   '')
    date_f   = request.args.get('date',   datetime.utcnow().strftime('%Y-%m-%d'))
    search_f = request.args.get('search', '')
    export   = request.args.get('export', '')

    query = (EntryLog.query
             .join(User, EntryLog.person_id == User.id)
             .filter(db.func.date(EntryLog.logged_at) == date_f))

    if type_f:   query = query.filter(EntryLog.log_type == type_f)
    if gate_f:   query = query.filter(EntryLog.gate == gate_f)
    if search_f: query = query.filter(
        db.or_(User.full_name.ilike(f'%{search_f}%'),
               User.user_id.ilike(f'%{search_f}%')))

    logs = query.order_by(EntryLog.logged_at.desc()).all()

    # CSV Export
    if export == '1':
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(['#','Name','ID','Role','Dept','Type','Gate','Guard','Method','Time'])
        for i, r in enumerate(logs, 1):
            writer.writerow([i, r.person.full_name, r.person.user_id,
                             r.person.role, r.person.department,
                             r.log_type, r.gate, r.guard.user_id,
                             r.method, r.logged_at.strftime('%Y-%m-%d %H:%M:%S')])
        output.seek(0)
        return Response(output, mimetype='text/csv',
                        headers={'Content-Disposition': f'attachment;filename=gate_log_{date_f}.csv'})

    return render_template('log.html', logs=logs,
        type_f=type_f, gate_f=gate_f, date_f=date_f, search_f=search_f,
        alert_count=unread_alert_count())


# ══════════════════════════════════════════════════════════
#  ROUTES — USER MANAGEMENT
# ══════════════════════════════════════════════════════════

@app.route('/users', methods=['GET', 'POST'])
@require_role('admin')
def users():
    if request.method == 'POST':
        action = request.form.get('action', '')

        # ── Add User ──
        if action == 'add':
            uid  = request.form.get('user_id','').strip()
            if User.query.filter_by(user_id=uid).first():
                flash(f"User ID '{uid}' already exists.", 'error')
            else:
                u = User(
                    user_id     = uid,
                    full_name   = request.form.get('full_name','').strip(),
                    role        = request.form.get('role','student'),
                    department  = request.form.get('department','').strip(),
                    email       = request.form.get('email','').strip(),
                    phone       = request.form.get('phone','').strip(),
                    password    = generate_password_hash(request.form.get('password','Admin@123')),
                    created_by  = current_user.id,
                )
                db.session.add(u)
                db.session.commit()
                log_audit(current_user.id, 'USER_CREATED', u.id,
                          f"Created {uid} ({u.full_name}) role={u.role}")
                flash(f'✅ User {u.full_name} created successfully.', 'success')

        # ── Toggle Status ──
        elif action == 'toggle':
            tid    = int(request.form.get('toggle_id', 0))
            new_st = request.form.get('new_status', '')
            reason = request.form.get('reason', '').strip()
            u = User.query.get_or_404(tid)
            if new_st in ('active', 'inactive'):
                u.status       = new_st
                u.deact_reason = reason if new_st == 'inactive' else None
                db.session.commit()
                log_audit(current_user.id, 'STATUS_CHANGED', tid,
                          f"Status → {new_st}. Reason: {reason}")
                if new_st == 'inactive':
                    create_alert('info', 'Account Deactivated',
                                 f"Admin {current_user.full_name} deactivated "
                                 f"{u.full_name} ({u.user_id}). Reason: {reason}",
                                 u.id, current_user.id)
                flash(f'✅ {u.full_name} status updated to {new_st}.', 'success')

        return redirect(url_for('users',
            role=request.args.get('role',''),
            status=request.args.get('status',''),
            search=request.args.get('search','')))

    # GET — list users with filters
    role_f   = request.args.get('role',   '')
    status_f = request.args.get('status', '')
    search_f = request.args.get('search', '')
    query = User.query
    if role_f:   query = query.filter_by(role=role_f)
    if status_f: query = query.filter_by(status=status_f)
    if search_f: query = query.filter(
        db.or_(User.full_name.ilike(f'%{search_f}%'),
               User.user_id.ilike(f'%{search_f}%')))
    user_list = query.order_by(User.role, User.full_name).all()

    return render_template('users.html', users=user_list,
        role_f=role_f, status_f=status_f, search_f=search_f,
        alert_count=unread_alert_count())


# ══════════════════════════════════════════════════════════
#  ROUTES — ALERTS
# ══════════════════════════════════════════════════════════

@app.route('/alerts', methods=['GET', 'POST'])
@require_role('supervisor')
def alerts():
    if request.method == 'POST':
        act = request.form.get('action', '')
        if act == 'mark_all':
            Alert.query.update({'is_read': True})
            db.session.commit()
            log_audit(current_user.id, 'ALERTS_MARKED_READ')
        elif act == 'mark_one':
            aid = int(request.form.get('alert_id', 0))
            a   = Alert.query.get(aid)
            if a:
                a.is_read = True
                db.session.commit()
        return redirect(url_for('alerts'))

    type_f = request.args.get('type', '')
    query  = Alert.query
    if type_f: query = query.filter_by(type=type_f)
    alert_list = query.order_by(Alert.created_at.desc()).all()

    counts = {
        'critical': Alert.query.filter_by(type='critical', is_read=False).count(),
        'warning' : Alert.query.filter_by(type='warning',  is_read=False).count(),
        'info'    : Alert.query.filter_by(type='info',     is_read=False).count(),
    }
    return render_template('alerts.html', alerts=alert_list, counts=counts,
        type_f=type_f, alert_count=unread_alert_count())


# ══════════════════════════════════════════════════════════
#  ROUTES — AUDIT LOG
# ══════════════════════════════════════════════════════════

@app.route('/audit')
@require_role('admin')
def audit():
    search_f = request.args.get('search', '')
    date_f   = request.args.get('date',   '')
    query    = AuditLog.query
    if search_f:
        query = query.filter(
            db.or_(AuditLog.action.ilike(f'%{search_f}%'),
                   AuditLog.details.ilike(f'%{search_f}%')))
    if date_f:
        query = query.filter(db.func.date(AuditLog.created_at) == date_f)
    audit_list = query.order_by(AuditLog.created_at.desc()).limit(200).all()

    # Load target users
    target_users = {}
    for e in audit_list:
        if e.target_id and e.target_id not in target_users:
            target_users[e.target_id] = User.query.get(e.target_id)

    return render_template('audit.html', audit_list=audit_list,
        target_users=target_users, search_f=search_f, date_f=date_f,
        alert_count=unread_alert_count())


# ══════════════════════════════════════════════════════════
#  ROUTES — REPORTS
# ══════════════════════════════════════════════════════════

@app.route('/reports')
@require_role('admin')
def reports():
    today = datetime.utcnow().date()
    stats = {
        'today_e'  : EntryLog.query.filter(EntryLog.log_type=='entry',   db.func.date(EntryLog.logged_at)==today).count(),
        'total_u'  : User.query.count(),
        'blocked'  : EntryLog.query.filter_by(log_type='blocked').count(),
        'audit_ev' : AuditLog.query.count(),
        'failed'   : LoginAttempt.query.filter_by(success=False).count(),
    }
    return render_template('reports.html', stats=stats,
                           alert_count=unread_alert_count())


# ══════════════════════════════════════════════════════════
#  DATABASE SEED
# ══════════════════════════════════════════════════════════

def seed_database():
    """Create tables and insert sample data if DB is empty."""
    db.create_all()
    if User.query.count() > 0:
        return  # Already seeded

    ph = generate_password_hash('Admin@123')
    sample_users = [
        User(user_id='ADMIN-001', full_name='Super Admin',        role='super_admin', department='Administration',  email='superadmin@jamia.edu',  password=ph, status='active'),
        User(user_id='ADMIN-002', full_name='Zafar Ahmed',        role='admin',       department='Administration',  email='zafar@jamia.edu',        password=ph, status='active'),
        User(user_id='PRIN-001',  full_name='Dr. Tariq Mahmood',  role='principal',   department='Principal Office',email='principal@jamia.edu',    password=ph, status='active'),
        User(user_id='WARD-001',  full_name='Hafiz Bilal',        role='warden',      department='Hostel Block A',  email='warden@jamia.edu',       password=ph, status='active'),
        User(user_id='SUP-001',   full_name='Tahir Hussain',      role='supervisor',  department='Security',        email='supervisor@jamia.edu',   password=ph, status='active'),
        User(user_id='GRD-004',   full_name='Hassan Ali',         role='guard',       department='Main Gate',       email='guard4@jamia.edu',       password=ph, status='active'),
        User(user_id='GRD-007',   full_name='Salman Khan',        role='guard',       department='East Gate',       email='guard7@jamia.edu',       password=ph, status='active'),
        User(user_id='GRD-009',   full_name='Imran Qureshi',      role='guard',       department='West Gate',       email='guard9@jamia.edu',       password=ph, status='inactive', deact_reason='Transferred'),
        User(user_id='STU-2021-001',full_name='Mohammad Arif',   role='student',     department='Computer Science',email='arif@jamia.edu',          password=ph, status='active'),
        User(user_id='STU-2022-089',full_name='Fatima Zahra',    role='student',     department='Islamic Studies', email='fatima@jamia.edu',        password=ph, status='active'),
        User(user_id='STU-2019-447',full_name='Ahmed Raza',      role='student',     department='Engineering',     email='ahmed@jamia.edu',         password=ph, status='inactive', deact_reason='Course Completed'),
        User(user_id='STU-2023-015',full_name='Zainab Malik',    role='student',     department='Mathematics',     email='zainab@jamia.edu',        password=ph, status='active'),
        User(user_id='STF-2018-012',full_name='Dr. Khalid Hassan',role='staff',      department='Administration',  email='khalid@jamia.edu',        password=ph, status='active'),
        User(user_id='STF-2015-003',full_name='Prof. Amina Shah',role='staff',       department='Arabic Dept.',    email='amina@jamia.edu',         password=ph, status='inactive', deact_reason='Retired'),
        User(user_id='STF-2020-007',full_name='Umar Farooq',     role='staff',       department='IT Department',   email='umar@jamia.edu',          password=ph, status='active'),
    ]
    db.session.add_all(sample_users)
    db.session.commit()
    print("✅ Database seeded with sample data.")


# ── Template helpers available in all templates ────────────
@app.context_processor
def inject_globals():
    return dict(
        now=datetime.utcnow,
        unread_alerts=unread_alert_count() if current_user.is_authenticated else 0
    )


# ── Run ────────────────────────────────────────────────────
if __name__ == '__main__':
    with app.app_context():
        seed_database()
    app.run(debug=False, host='0.0.0.0', port=int(os.getenv('PORT', 5000)))
