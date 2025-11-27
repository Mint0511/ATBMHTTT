from flask import Flask, render_template, request, redirect, url_for, flash, session, send_file, Response, abort
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import sqlite3, os, datetime, smtplib, secrets, base64
from email.message import EmailMessage
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.exceptions import InvalidTag
import io
import mimetypes

# Fix MIME type for .mjs files on Windows
mimetypes.add_type('application/javascript', '.mjs')

app = Flask(__name__)
# Use a fixed secret key for demo stability (prevents session invalidation on restart)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'fixed_secret_key_for_demo_123456789')
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'
app.config['SESSION_COOKIE_SECURE'] = False  # Đặt True nếu dùng HTTPS
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# --- Database ---
import os as os_module
db_path = os_module.path.join(os_module.path.dirname(os_module.path.abspath(__file__)), 'exam.db')
conn = sqlite3.connect(db_path, check_same_thread=False)
c = conn.cursor()

# Drop legacy tables no longer used (cleanup for simplified model)
for _tbl in ['posts', 'comments', 'exam_keys']:
    try:
        c.execute(f"DROP TABLE IF EXISTS {_tbl}")
    except Exception:
        pass

# Create tables if not exists
c.execute('''CREATE TABLE IF NOT EXISTS users
             (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password TEXT, role TEXT, email TEXT UNIQUE, rsa_private BLOB, salt TEXT, full_name TEXT, student_id TEXT, class_name TEXT, status TEXT DEFAULT 'approved', approval_note TEXT, selected_teachers TEXT, teacher_id TEXT, failed_attempts INTEGER DEFAULT 0, lock_until TEXT, is_deleted INTEGER DEFAULT 0)''')

try:
    c.execute("ALTER TABLE users ADD COLUMN status TEXT DEFAULT 'approved'")
except:
    pass

try:
    c.execute("ALTER TABLE users ADD COLUMN selected_teachers TEXT")
except:
    pass

try:
    c.execute("ALTER TABLE users ADD COLUMN teacher_id TEXT")
except:
    pass
try:
    c.execute("ALTER TABLE users ADD COLUMN failed_attempts INTEGER DEFAULT 0")
except:
    pass
try:
    c.execute("ALTER TABLE users ADD COLUMN lock_until TEXT")
except:
    pass
try:
    c.execute("ALTER TABLE users ADD COLUMN is_deleted INTEGER DEFAULT 0")
except:
    pass
try:
    c.execute("ALTER TABLE users ADD COLUMN is_locked INTEGER DEFAULT 0")
except:
    pass

"""Exam table (legacy schema keeps aes_key). We will store RSA-wrapped key in encrypted_aes_key instead of plaintext aes_key."""
c.execute('''CREATE TABLE IF NOT EXISTS exams
             (id INTEGER PRIMARY KEY AUTOINCREMENT, filename TEXT, enc_path TEXT, release_time TEXT, expire_time TEXT, teacher_id INTEGER, ten_de TEXT, aes_key BLOB)''')

try:
    c.execute("ALTER TABLE exams ADD COLUMN aes_key BLOB")
except:
    pass
try:
    c.execute("ALTER TABLE exams ADD COLUMN encrypted_aes_key BLOB")
except:
    pass

try:
    c.execute("ALTER TABLE exams ADD COLUMN allowed_students TEXT DEFAULT ''")
except:
    pass

c.execute('''CREATE TABLE IF NOT EXISTS groups
             (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, teacher_id INTEGER, description TEXT, aes_key BLOB, code TEXT)''')

try:
    c.execute("ALTER TABLE groups ADD COLUMN code TEXT")
except:
    pass

c.execute('''CREATE TABLE IF NOT EXISTS group_members
             (id INTEGER PRIMARY KEY AUTOINCREMENT, group_id INTEGER, student_id INTEGER, status TEXT DEFAULT 'pending')''')

try:
    c.execute("ALTER TABLE group_members ADD COLUMN note TEXT")
except:
    pass

try:
    c.execute("ALTER TABLE group_members ADD COLUMN student_note TEXT")
except:
    pass



# Đã loại bỏ bảng posts/comments để đơn giản hoá (chỉ còn nhóm phục vụ phân quyền đề thi)

c.execute('''CREATE TABLE IF NOT EXISTS audit_logs
             (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, exam_id INTEGER, action TEXT, timestamp TEXT, ip_address TEXT)''')

try:
    c.execute("ALTER TABLE exams ADD COLUMN signature BLOB")
except:
    pass

try:
    c.execute("ALTER TABLE exams ADD COLUMN file_hash TEXT")
except:
    pass

try:
    c.execute("ALTER TABLE exams ADD COLUMN pin_code TEXT")
except:
    pass

try:
    c.execute("ALTER TABLE exams ADD COLUMN auth_mode TEXT DEFAULT 'both'")
except:
    pass

try:
    c.execute("ALTER TABLE exams ADD COLUMN allowed_groups TEXT")
except:
    pass


# Bảng exam_keys (per-student key) đã bỏ khỏi mô hình (giữ nguyên nếu còn dữ liệu cũ, không sử dụng)

# Bảng submissions cho nộp bài
c.execute('''CREATE TABLE IF NOT EXISTS submissions
             (id INTEGER PRIMARY KEY AUTOINCREMENT, exam_id INTEGER, student_id INTEGER, filename TEXT, enc_path TEXT, submission_time TEXT, aes_key BLOB, encrypted_aes_key BLOB, file_hash TEXT)''')

try:
    c.execute("ALTER TABLE submissions ADD COLUMN filename TEXT")
except:
    pass

try:
    c.execute("ALTER TABLE submissions ADD COLUMN enc_path TEXT")
except:
    pass

try:
    c.execute("ALTER TABLE submissions ADD COLUMN encrypted_aes_key BLOB")
except:
    pass

try:
    c.execute("ALTER TABLE submissions ADD COLUMN file_hash TEXT")
except:
    pass

try:
    c.execute("ALTER TABLE submissions ADD COLUMN score REAL")
except:
    pass

try:
    c.execute("ALTER TABLE submissions ADD COLUMN teacher_note TEXT")
except:
    pass

try:
    c.execute("ALTER TABLE submissions ADD COLUMN graded_time TEXT")
except:
    pass

c.execute('''CREATE TABLE IF NOT EXISTS config
             (id INTEGER PRIMARY KEY AUTOINCREMENT, key TEXT UNIQUE, value TEXT)''')

# Default config
for k, v in [('mail_username',''),('mail_password',''),('school_name','Trường Đại học Sài Gòn'),
             ('default_release_offset','1'), ('default_expire_minutes','120'), ('default_subject','')]:
    c.execute("INSERT OR IGNORE INTO config(key,value) VALUES (?,?)",(k,v))

# Migrate old config key
if c.execute("SELECT 1 FROM config WHERE key='default_expire_hours'").fetchone():
    c.execute("INSERT OR REPLACE INTO config(key,value) VALUES ('default_expire_minutes','120')")
    c.execute("DELETE FROM config WHERE key='default_expire_hours'")

# Create default admin if not exists
if not c.execute("SELECT 1 FROM users WHERE role='admin'").fetchone():
    salt = os.urandom(16).hex()
    hashed = generate_password_hash('admin123' + salt)
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(b'passphrase_default')
    )
    c.execute("INSERT INTO users(username,password,role,email,rsa_private,salt,full_name,student_id,class_name) VALUES (?,?,?,?,?,?,?,?,?)",
              ('admin', hashed, 'admin', 'admin@school.com', pem, salt, 'Administrator', '', ''))

conn.commit()

# --- Login manager ---
login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(UserMixin):
    def __init__(self, id, username, role, email):
        self.id = id
        self.username = username
        self.role = role
        self.email = email

@login_manager.user_loader
def load_user(uid):
    row = c.execute("SELECT id, username, role, email FROM users WHERE id=?",(uid,)).fetchone()
    return User(*row) if row else None

# --- Helper functions ---
# Đã bỏ mã hoá nội dung nhóm.

def parse_datetime(datetime_str):
    """Parse datetime string with flexible format supporting microseconds"""
    if not datetime_str:
        return None
    try:
        # Try with microseconds first
        return datetime.datetime.fromisoformat(datetime_str)
    except:
        try:
            # Try standard format without microseconds
            return datetime.datetime.strptime(datetime_str, '%Y-%m-%dT%H:%M')
        except:
            try:
                # Try with seconds
                return datetime.datetime.strptime(datetime_str, '%Y-%m-%dT%H:%M:%S')
            except:
                # Last resort: return current time
                return datetime.datetime.now()

def sign_data(data, private_key_pem):
    """Sign data with RSA private key"""
    private_key = serialization.load_pem_private_key(
        private_key_pem,
        password=b'passphrase_default'
    )
    signature = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

def verify_signature(data, signature, private_key_pem):
    """Verify RSA signature"""
    try:
        private_key = serialization.load_pem_private_key(
            private_key_pem,
            password=b'passphrase_default'
        )
        public_key = private_key.public_key()
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except:
        return False

def log_audit(user_id, exam_id, action, ip_address):
    """Log user actions for audit trail"""
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    c.execute("INSERT INTO audit_logs(user_id, exam_id, action, timestamp, ip_address) VALUES (?,?,?,?,?)",
              (user_id, exam_id, action, timestamp, ip_address))
    conn.commit()

def rsa_encrypt_key(aes_key, private_key_pem):
    """Encrypt AES key using public key derived from stored private key."""
    private_key = serialization.load_pem_private_key(
        private_key_pem,
        password=b'passphrase_default'
    )
    public_key = private_key.public_key()
    return public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def rsa_decrypt_key(encrypted_key, private_key_pem):
    """Decrypt AES key with RSA private key"""
    private_key = serialization.load_pem_private_key(
        private_key_pem,
        password=b'passphrase_default'
    )
    decrypted = private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted

def hash_file(data):
    """Hash file content with SHA-256 for integrity check"""
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)
    return digest.finalize().hex()

# --- CSRF & Security Headers ---
@app.before_request
def ensure_csrf_token():
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(16)

def verify_csrf():
    if request.method == 'POST':
        form_token = request.form.get('csrf_token','')
        if not form_token or form_token != session.get('csrf_token'):
            abort(400, description='CSRF token invalid')

@app.after_request
def set_security_headers(resp):
    # Cho phép iframe cùng nguồn gốc (để hiển thị PDF)
    resp.headers['X-Frame-Options'] = 'SAMEORIGIN'
    resp.headers['X-Content-Type-Options'] = 'nosniff'
    resp.headers['Referrer-Policy'] = 'no-referrer'
    # Cập nhật CSP: Thêm 'unsafe-inline' vào script-src để chạy được script trong view_exam.html
    # Thêm sandbox cho iframe để chặn download, in ấn, script trong iframe (nếu cần)
    # sandbox="allow-scripts allow-same-origin" là tối thiểu để PDF.js hoạt động nhưng chặn download native
    resp.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' https://cdn.jsdelivr.net 'unsafe-inline' blob:; worker-src 'self' blob:; style-src 'self' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com 'unsafe-inline'; font-src 'self' https://cdnjs.cloudflare.com; img-src 'self' data:; frame-ancestors 'self'; object-src 'none'"
    return resp

# --- Routes ---
@app.route('/')
def index(): return redirect('/login')

@app.route('/register', methods=['GET','POST'])
def register():
    teachers = c.execute("SELECT id, username, full_name FROM users WHERE role='teacher'").fetchall()
    groups = c.execute("SELECT id, name, teacher_id, code FROM groups").fetchall()
    errors = []
    if request.method=='POST':
        verify_csrf()
        u = request.form['username'].strip()
        p = request.form['password']
        r = request.form['role']
        e = request.form['email'].strip().lower()
        full_name = request.form.get('full_name', '').strip()
        student_id = request.form.get('student_id', '').strip()
        class_name = request.form.get('class_name', '').strip()
        selected_groups = request.form.getlist('groups')  # list of group ids
        
        # Validation
        if len(p)<6: 
            errors.append('Mật khẩu phải ≥6 ký tự')
        if r != 'student': 
            errors.append('Chỉ được đăng ký sinh viên')
        if c.execute("SELECT 1 FROM users WHERE username=? AND is_deleted=0",(u,)).fetchone(): 
            errors.append('Username tồn tại')
        if c.execute("SELECT 1 FROM users WHERE email=? AND is_deleted=0",(e,)).fetchone(): 
            errors.append('Email tồn tại')
        # Validate student_id
        if not student_id.startswith('3122410') or len(student_id) != 10 or not student_id[7:].isdigit():
            errors.append('Mã sinh viên phải có định dạng 3122410xxx (xxx là 3 chữ số)')
        if c.execute("SELECT 1 FROM users WHERE student_id=? AND is_deleted=0",(student_id,)).fetchone(): 
            errors.append('Mã sinh viên đã tồn tại, vui lòng nhập mã khác')
        
        if errors:
            return render_template('auth.html', mode='register', teachers=teachers, groups=groups, errors=errors)
        
        salt = os.urandom(16).hex()
        hashed = generate_password_hash(p + salt)
        # RSA private key
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(b'passphrase_default')
        )
        uid = c.execute("INSERT INTO users(username,password,role,email,rsa_private,salt,full_name,student_id,class_name,status) VALUES (?,?,?,?,?,?,?,?,?,?)",
                        (u, hashed, r, e, pem, salt, full_name, student_id, class_name, 'pending')).lastrowid
        # Add to group_members
        for gid in selected_groups:
            c.execute("INSERT INTO group_members(group_id, student_id) VALUES (?,?)", (gid, uid))
        conn.commit()
        flash('✅ Đăng ký tài khoản thành công! Vui lòng đợi giáo viên duyệt yêu cầu trước khi đăng nhập. Bạn sẽ nhận được email thông báo.', 'success')
        return redirect('/login')
    return render_template('auth.html', mode='register', teachers=teachers, groups=groups)

@app.route('/login', methods=['GET','POST'])
def login():
    errors = []
    if request.method=='POST':
        verify_csrf()
        u = request.form['username']
        p = request.form['password']
        row = c.execute("SELECT id,password,salt,role,email,status,failed_attempts,lock_until,is_deleted,is_locked FROM users WHERE username=? AND is_deleted=0",(u,)).fetchone()
        if row:
            # Check if account is locked by admin
            is_locked = row[9] if len(row) > 9 else 0
            if is_locked:
                errors.append('❌ Tài khoản đã bị khóa bởi quản trị viên. Vui lòng liên hệ admin để được hỗ trợ.')
                return render_template('auth.html', mode='login', errors=errors)
            
            # Lockout check (temporary lock from failed attempts)
            lock_until = row[7]
            if lock_until:
                try:
                    lu = datetime.datetime.fromisoformat(lock_until)
                    if datetime.datetime.now() < lu:
                        errors.append('⏱️ Tài khoản bị khóa tạm thời 5 phút do đăng nhập sai quá 5 lần. Vui lòng thử lại sau.')
                        return render_template('auth.html', mode='login', errors=errors)
                except:
                    pass
        if row and check_password_hash(row[1], p + row[2]) and row[5] == 'approved':
            login_user(User(row[0], u, row[3], row[4]))
            c.execute("UPDATE users SET failed_attempts=0, lock_until=NULL WHERE id=?", (row[0],))
            conn.commit()
            if row[3] == 'admin':
                return redirect('/admin/users')
            return redirect('/dashboard')
        elif row and row[5] != 'approved':
            errors.append('⏳ Tài khoản đang chờ giáo viên duyệt hoặc đã bị từ chối. Vui lòng liên hệ giáo viên.')
        else:
            errors.append('❌ Sai tên đăng nhập hoặc mật khẩu. Vui lòng kiểm tra và thử lại.')
            if row:
                attempts = (row[6] or 0) + 1
                if attempts >= 5:
                    lock_until_time = (datetime.datetime.now() + datetime.timedelta(minutes=5)).isoformat(timespec='seconds')
                    c.execute("UPDATE users SET failed_attempts=0, lock_until=? WHERE id=?", (lock_until_time, row[0]))
                else:
                    c.execute("UPDATE users SET failed_attempts=? WHERE id=?", (attempts, row[0]))
                conn.commit()
    return render_template('auth.html', mode='login', errors=errors)

# ----- LOGOUT -----
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect('/login')

# ----- DASHBOARD -----
@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.role == 'admin':
        # Admin redirect to user management
        return redirect(url_for('admin_users'))
    
    now = datetime.datetime.now()
    if current_user.role=='teacher':
        # Get user info
        user_info = c.execute("SELECT username, email, full_name, teacher_id, class_name FROM users WHERE id=?", (current_user.id,)).fetchone()
        user_data = {
            'username': user_info[0],
            'email': user_info[1] or 'Chưa cập nhật',
            'full_name': user_info[2] or 'Chưa cập nhật',
            'teacher_id': user_info[3] or 'Chưa cập nhật',
            'class_name': user_info[4] or 'Chưa cập nhật'
        }
        
        exams = c.execute("SELECT id, filename, release_time, expire_time, ten_de, pin_code, allowed_groups FROM exams WHERE teacher_id=?",(current_user.id,)).fetchall()
        # Group exams by allowed_groups
        group_data = {}
        for e in exams:
            eid, filename, release_str, expire_str, ten_de, pin_code, allowed_groups_str = e
            
            release_time = parse_datetime(release_str)
            expire_time = parse_datetime(expire_str)
            release_display = release_time.strftime('%d/%m/%Y %H:%M')
            expire_display = expire_time.strftime('%d/%m/%Y %H:%M')
            
            # Determine status
            if now < release_time:
                status = 'upcoming'  # Chưa mở
            elif now > expire_time:
                status = 'expired'  # Đã hết hạn
            else:
                status = 'active'  # Đang mở
            
            exam_data = (eid, filename, release_display, expire_display, ten_de, pin_code or "N/A", status)
            
            # Process groups
            if allowed_groups_str:
                group_ids = allowed_groups_str.split(',')
                for gid in group_ids:
                    gid = gid.strip()
                    if not gid:
                        continue
                    if gid not in group_data:
                        # Get group name
                        group_row = c.execute("SELECT name FROM groups WHERE id=?", (gid,)).fetchone()
                        group_name = group_row[0] if group_row else f"Lớp {gid}"
                        group_data[gid] = {'name': group_name, 'exams': []}
                    group_data[gid]['exams'].append(exam_data)
            else:
                # No group assigned, put in "Chưa phân lớp"
                if 'unassigned' not in group_data:
                    group_data['unassigned'] = {'name': 'Chưa phân lớp', 'exams': []}
                group_data['unassigned']['exams'].append(exam_data)
        
        return render_template('dashboard_teacher.html', group_data=group_data, user_info=user_data)
    else:
        # Get user info
        user_info = c.execute("SELECT username, email, full_name, student_id, class_name FROM users WHERE id=?", (current_user.id,)).fetchone()
        user_data = {
            'username': user_info[0],
            'email': user_info[1] or 'Chưa cập nhật',
            'full_name': user_info[2] or 'Chưa cập nhật',
            'student_id': user_info[3] or 'Chưa cập nhật',
            'class_name': user_info[4] or 'Chưa cập nhật'
        }
        
        exams = c.execute("SELECT e.id, e.filename, e.release_time, e.expire_time, u.username, e.ten_de, e.allowed_groups, e.auth_mode FROM exams e LEFT JOIN users u ON e.teacher_id=u.id").fetchall()
        # Add status
        exams_with_status = []
        # Get student's groups
        student_groups = c.execute("SELECT group_id FROM group_members WHERE student_id=? AND status='approved'", (current_user.id,)).fetchall()
        student_group_ids = [str(g[0]) for g in student_groups]
        
        for e in exams:
            eid, filename, release_str, expire_str, username, ten_de, allowed_groups, auth_mode = e
            # Check if student is in allowed groups
            if allowed_groups:
                exam_group_ids = allowed_groups.split(',')
                has_permission = any(gid in student_group_ids for gid in exam_group_ids)
                if not has_permission:
                    continue  # Skip if not in any allowed group
            release_time = parse_datetime(release_str)
            expire_time = parse_datetime(expire_str)
            release_display = release_time.strftime('%d/%m/%Y %H:%M')
            expire_display = expire_time.strftime('%d/%m/%Y %H:%M')
            if now < release_time:
                status = 'Chưa mở'
                status_class = 'text-warning'
            elif now > expire_time:
                status = 'Đã hết hạn'
                status_class = 'text-danger'
            else:
                status = 'Đang mở'
                status_class = 'text-success'
            exams_with_status.append((eid, filename, release_display, expire_display, username, ten_de, status, status_class, auth_mode))
        # Get groups for student
        groups = c.execute("""
            SELECT g.id, g.name, u.username as teacher_name
            FROM groups g
            JOIN group_members gm ON g.id = gm.group_id
            JOIN users u ON g.teacher_id = u.id
            WHERE gm.student_id=? AND gm.status='approved'
        """, (current_user.id,)).fetchall()
        
        rejected_requests = c.execute("""
            SELECT g.name, u.username as teacher_name, gm.note, gm.group_id
            FROM groups g
            JOIN group_members gm ON g.id = gm.group_id
            JOIN users u ON g.teacher_id = u.id
            WHERE gm.student_id=? AND gm.status='rejected'
        """, (current_user.id,)).fetchall()
        
        return render_template('dashboard_student.html', exams=exams_with_status, groups=groups, rejected_requests=rejected_requests, user_info=user_data)

# ----- UPLOAD (TEACHER) -----
@app.route('/upload', methods=['GET','POST'])
@login_required
def upload():
    if current_user.role!='teacher': return redirect('/dashboard')
    groups = c.execute("SELECT id, name FROM groups WHERE teacher_id=?", (current_user.id,)).fetchall()
    errors = []
    if request.method=='POST':
        verify_csrf()
        if 'file' not in request.files or not request.files['file'].filename:
            errors.append('Chưa chọn file!')
            return render_template('upload.html', groups=groups, errors=errors)
        file = request.files['file']
        ten_de = request.form['ten_de'].strip()
        release_date_str = request.form['release_date']
        release_time_str = request.form['release_time']
        expire_date_str = request.form.get('expire_date', '')
        expire_time_str = request.form.get('expire_time', '')
        selected_groups = request.form.getlist('allowed_groups')  # List of group ids
        allowed_students = ''
        if selected_groups:
            # Get all students in selected groups
            placeholders = ','.join('?' for _ in selected_groups)
            students = c.execute(f"SELECT DISTINCT u.username FROM users u JOIN group_members gm ON u.id=gm.student_id WHERE gm.group_id IN ({placeholders}) AND u.status='approved'", selected_groups).fetchall()
            allowed_students = ','.join([s[0] for s in students])
        # Check if PDF
        if not file.filename.lower().endswith('.pdf') or file.mimetype != 'application/pdf':
            errors.append('📄 Chỉ chấp nhận file định dạng PDF! File của bạn không đúng định dạng.')
            return render_template('upload.html', groups=groups, errors=errors)
        # Validate
        try: 
            release_time = datetime.datetime.strptime(f"{release_date_str} {release_time_str}", '%Y-%m-%d %H:%M')
            if expire_date_str and expire_time_str:
                expire_time = datetime.datetime.strptime(f"{expire_date_str} {expire_time_str}", '%Y-%m-%d %H:%M')
            else:
                expire_time = release_time + datetime.timedelta(minutes=120)  # Default 2 hours
        except Exception as e:
            errors.append(f'❌ Sai định dạng thời gian: {str(e)}')
            return render_template('upload.html', groups=groups, errors=errors)
        
        # Check if release_time is in the past
        now = datetime.datetime.now()
        if release_time < now:
            errors.append(f'⏰ Thời gian mở đề không được trong quá khứ! Hiện tại: {now.strftime("%d/%m/%Y %H:%M")}')
            return render_template('upload.html', groups=groups, errors=errors)
        
        # Check if expire_time is before release_time
        if expire_time <= release_time:
            errors.append('⏰ Thời gian đóng đề phải sau thời gian mở đề! Vui lòng kiểm tra lại.')
            return render_template('upload.html', groups=groups, errors=errors)
        
        # Check minimum duration (at least 10 minutes)
        duration_minutes = (expire_time - release_time).total_seconds() / 60
        if duration_minutes < 10:
            errors.append(f'⏱️ Thời lượng thi phải ít nhất 10 phút! Hiện tại: {int(duration_minutes)} phút.')
            return render_template('upload.html', groups=groups, errors=errors)
        filename = secure_filename(file.filename)
        raw_data = file.read()
        
        # STEP 1: Hash file gốc (SHA-256) để kiểm tra và ký
        file_hash = hash_file(raw_data)

        # STEP 2: AES-256-GCM Encryption (không padding)
        aes_key = os.urandom(32)
        iv = os.urandom(12)
        encryptor = Cipher(algorithms.AES(aes_key), modes.GCM(iv)).encryptor()
        ct = encryptor.update(raw_data) + encryptor.finalize()
        tag = encryptor.tag

        enc_path = os.path.join(app.config['UPLOAD_FOLDER'], f"enc_{filename}")
        with open(enc_path, 'wb') as f:
            f.write(base64.b64encode(iv + tag + ct))


        # STEP 3: Digital Signature trên hash (non-repudiation)
        row = c.execute("SELECT rsa_private FROM users WHERE id=?", (current_user.id,)).fetchone()
        teacher_private_key = row[0] if row and row[0] else None
        # Nếu chưa có khóa RSA thì tự động sinh và lưu vào DB
        if not teacher_private_key:
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric import rsa
            private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.BestAvailableEncryption(b'passphrase_default')
            )
            c.execute("UPDATE users SET rsa_private=? WHERE id=?", (pem, current_user.id))
            conn.commit()
            teacher_private_key = pem
        signature = sign_data(bytes.fromhex(file_hash), teacher_private_key)

        # STEP 4: RSA bọc AES key (1 lần, không per-student)
        encrypted_aes_key = rsa_encrypt_key(aes_key, teacher_private_key)

        # Tạo mã PIN ngẫu nhiên 6 số cho đề thi (dùng cho thi offline)
        pin_code = ''.join(secrets.choice('0123456789') for _ in range(6))
        
        # Lấy auth_mode từ form
        auth_mode = request.form.get('auth_mode', 'pin')
        
        allowed_groups_str = ','.join(selected_groups)

        # Lưu exam (aes_key plaintext = NULL; encrypted_aes_key thay thế)
        exam_id = c.execute("INSERT INTO exams(filename,enc_path,release_time,expire_time,teacher_id,ten_de,aes_key,allowed_students,signature,file_hash,encrypted_aes_key,pin_code,auth_mode,allowed_groups) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                            (filename, enc_path, release_time.strftime('%Y-%m-%dT%H:%M'), expire_time.strftime('%Y-%m-%dT%H:%M'), current_user.id, ten_de, None, allowed_students, signature, file_hash, encrypted_aes_key, pin_code, auth_mode, allowed_groups_str)).lastrowid

        conn.commit()
        session['success_message'] = f'Upload thành công! Mã PIN: {pin_code} (Chế độ: {auth_mode})'
        return redirect('/dashboard')
    return render_template('upload.html', groups=groups, errors=errors)

# ----- VERIFY OTP & VIEW -----
@app.route('/view_exam/<int:eid>', methods=['GET','POST'])
@login_required
def view_exam(eid):
    if request.method == 'POST':
        verify_csrf()
        row = c.execute("SELECT release_time, expire_time, allowed_groups, pin_code, auth_mode FROM exams WHERE id=?",(eid,)).fetchone()
        if not row: flash('Không tìm thấy đề thi'); return redirect(url_for('dashboard'))
        release_time_str, expire_time_str, allowed_groups, pin_code, auth_mode = row
        if not auth_mode: auth_mode = 'pin' # Default for old records
        
        # Check permission by groups
        if allowed_groups:
            student_groups = c.execute("SELECT group_id FROM group_members WHERE student_id=? AND status='approved'", (current_user.id,)).fetchall()
            student_group_ids = [str(g[0]) for g in student_groups]
            exam_group_ids = allowed_groups.split(',')
            has_permission = any(gid in student_group_ids for gid in exam_group_ids)
            if not has_permission:
                flash('🔒 Bạn không có quyền truy cập đề thi này. Vui lòng tham gia lớp học có đề thi này.', 'danger'); return redirect(url_for('dashboard'))
        now = datetime.datetime.now()
        release_time = parse_datetime(release_time_str)
        expire_time = parse_datetime(expire_time_str)
        if now < release_time: flash('Đề thi chưa mở!'); return redirect(url_for('dashboard'))
        if now > expire_time: flash('Đề thi đã hết hạn!'); return redirect(url_for('dashboard'))
        
        # Check PIN
        pin_input = request.form.get('pin_input', '').strip()
        if not pin_code: 
             flash('❌ Đề thi này chưa được giáo viên thiết lập mã PIN.', 'warning'); return redirect(url_for('view_exam', eid=eid))
        if pin_input != pin_code:
            flash('❌ Mã PIN không đúng! Vui lòng nhập đúng mã ca thi mà giáo viên cung cấp.', 'danger'); return redirect(url_for('view_exam', eid=eid))
        # Success with PIN
            
        row = c.execute("SELECT ten_de, expire_time FROM exams WHERE id=?", (eid,)).fetchone()
        exam_title = row[0] if row else "Đề Thi"
        expire_time_iso = row[1] if row else ""
        return render_template('view_exam.html', file_url=url_for('stream_exam', eid=eid), exam_title=exam_title, eid=eid, expire_time=expire_time_iso)
    
    # GET: show form
    row = c.execute("SELECT ten_de, auth_mode FROM exams WHERE id=?", (eid,)).fetchone()
    exam_title = row[0] if row else "Đề Thi"
    auth_mode = row[1] if row else "pin"
    return render_template('view_exam.html', exam_title=exam_title, eid=eid, auth_mode=auth_mode)

@app.route('/download_encrypted/<int:eid>')
@login_required
def download_encrypted(eid):
    row = c.execute("SELECT enc_path, filename, allowed_groups, release_time, expire_time FROM exams WHERE id=?", (eid,)).fetchone()
    if not row: return Response("Lỗi: Không tìm thấy file", status=404)
    enc_path, filename, allowed_groups, release_time_str, expire_time_str = row
    
    # Check permissions (same as view_exam)
    if current_user.role == 'student':
        if allowed_groups:
            student_groups = c.execute("SELECT group_id FROM group_members WHERE student_id=? AND status='approved'", (current_user.id,)).fetchall()
            student_group_ids = [str(g[0]) for g in student_groups]
            exam_group_ids = allowed_groups.split(',')
            has_permission = any(gid in student_group_ids for gid in exam_group_ids)
            if not has_permission:
                return Response("Lỗi: Không có quyền truy cập", status=403)
        now = datetime.datetime.now()
        release_time = parse_datetime(release_time_str)
        expire_time = parse_datetime(expire_time_str)
        # Allow downloading encrypted file even if not yet open? 
        # Usually for demo purposes, yes, we want to show it's encrypted.
        # But strictly speaking, maybe we should respect release time.
        # However, since it's encrypted and they can't decrypt it without the key (which is released via OTP/server logic), 
        # giving them the blob is safe-ish and good for demo.
        # Let's keep the time check to be consistent with "viewing" the exam entry.
        if now < release_time or now > expire_time: 
             # For demo, maybe we allow it? The user said "show cho thầy coi".
             # Let's stick to the rules: if they can see the exam in dashboard, they can download the encrypted blob.
             pass 

    return send_file(enc_path, as_attachment=True, download_name=f"ENCRYPTED_{filename}")

@app.route('/stream_exam/<int:eid>')
@login_required
def stream_exam(eid):
    row = c.execute("SELECT enc_path, encrypted_aes_key, release_time, expire_time, allowed_groups, teacher_id, signature, file_hash FROM exams WHERE id=?", (eid,)).fetchone()
    if not row: return Response("Lỗi: Không tìm thấy file", status=404)
    enc_path, encrypted_aes_key, release_time_str, expire_time_str, allowed_groups, teacher_id, signature, file_hash = row
    
    # Check permission by groups
    if allowed_groups:
        student_groups = c.execute("SELECT group_id FROM group_members WHERE student_id=? AND status='approved'", (current_user.id,)).fetchall()
        student_group_ids = [str(g[0]) for g in student_groups]
        exam_group_ids = allowed_groups.split(',')
        has_permission = any(gid in student_group_ids for gid in exam_group_ids)
        if not has_permission:
            return Response("Lỗi: Không có quyền truy cập", status=403)
    
    now = datetime.datetime.now()
    release_time = parse_datetime(release_time_str)
    expire_time = parse_datetime(expire_time_str)
    if now < release_time or now > expire_time: return Response("Lỗi: Đề thi không khả dụng", status=403)
    
    try:
        with open(enc_path,'rb') as f:
            data = base64.b64decode(f.read())
        
        # STEP 1: RSA unwrap AES key (server-side)
        teacher_row = c.execute("SELECT rsa_private FROM users WHERE id=?", (teacher_id,)).fetchone()
        if not teacher_row:
            return Response("Lỗi: Không tìm thấy khóa giáo viên", status=500)
        decrypted_aes_key = rsa_decrypt_key(encrypted_aes_key, teacher_row[0]) if encrypted_aes_key else b'\x00'*32

        # Log audit
        log_audit(current_user.id, eid, 'view_exam', request.remote_addr)

        # STEP 2: AES-GCM Decryption
        iv, tag, ct = data[:12], data[12:28], data[28:]
        decryptor = Cipher(algorithms.AES(decrypted_aes_key), modes.GCM(iv, tag)).decryptor()
        decrypted = decryptor.update(ct) + decryptor.finalize()

        # STEP 3: Verify hash & signature
        if file_hash:
            computed_hash = hash_file(decrypted)
            if computed_hash != file_hash:
                return Response("Lỗi: File hash không khớp!", status=500)
            if signature and not verify_signature(bytes.fromhex(file_hash), signature, teacher_row[0]):
                return Response("Lỗi: Chữ ký không hợp lệ!", status=403)
        
        if not decrypted.startswith(b'%PDF'):
            return Response("Lỗi: File giải mã không phải PDF hợp lệ", status=500)
    except InvalidTag:
        return Response("CẢNH BÁO BẢO MẬT: PHÁT HIỆN FILE BỊ CAN THIỆP TRÁI PHÉP!\n(Integrity Check Failed - Authentication Tag không khớp)", status=403)
    except Exception as e:
        return Response(f"Lỗi giải mã: {str(e)}", status=500)
    return send_file(io.BytesIO(decrypted), mimetype='application/pdf')

# ----- STREAM EXAM FOR TEACHER -----
@app.route('/stream_exam_teacher/<int:eid>')
@login_required
def stream_exam_teacher(eid):
    if current_user.role != 'teacher':
        return Response("Lỗi: Không có quyền", status=403)
    row = c.execute("SELECT enc_path, encrypted_aes_key, teacher_id FROM exams WHERE id=?", (eid,)).fetchone()
    if not row or row[2] != current_user.id:
        return Response("Lỗi: Không có quyền truy cập", status=403)
    enc_path, encrypted_aes_key, _ = row
    # Decrypt file
    try:
        with open(enc_path,'rb') as f:
            data = base64.b64decode(f.read())
        iv, tag, ct = data[:12], data[12:28], data[28:]
        teacher_row = c.execute("SELECT rsa_private FROM users WHERE id=?", (current_user.id,)).fetchone()
        decrypted_aes_key = rsa_decrypt_key(encrypted_aes_key, teacher_row[0]) if encrypted_aes_key else b'\x00'*32
        decryptor = Cipher(algorithms.AES(decrypted_aes_key), modes.GCM(iv, tag)).decryptor()
        decrypted = decryptor.update(ct) + decryptor.finalize()
        if not decrypted.startswith(b'%PDF'):
            return Response("Lỗi: File giải mã không phải PDF hợp lệ", status=500)
    except Exception as e:
        return Response(f"Lỗi giải mã: {str(e)}", status=500)
    return send_file(io.BytesIO(decrypted), mimetype='application/pdf')

# ----- DELETE EXAM (TEACHER) -----
@app.route('/delete_exam/<int:eid>')
@login_required
def delete_exam(eid):
    if current_user.role != 'teacher':
        return redirect('/dashboard')
    row = c.execute("SELECT enc_path, teacher_id FROM exams WHERE id=?", (eid,)).fetchone()
    if not row or row[1] != current_user.id:
        flash('Không có quyền xóa')
        return redirect('/dashboard')
    enc_path = row[0]
    c.execute("DELETE FROM exams WHERE id=?", (eid,))
    conn.commit()
    if os.path.exists(enc_path):
        os.remove(enc_path)
    flash('🗑️ Đã xóa đề thi thành công!', 'success')
    return redirect('/dashboard')

# ----- APPROVE STUDENTS (TEACHER) -----
@app.route('/teacher/approve_students', methods=['GET','POST'])
@login_required
def approve_students():
    if current_user.role != 'teacher':
        return redirect('/dashboard')
    if request.method == 'POST':
        verify_csrf()
        action = request.form.get('action')
        uid = request.form['user_id']
        gid = request.form['group_id']  # Add group_id
        note = request.form.get('note', '').strip()
        # Check if membership exists and pending
        row = c.execute("SELECT 1 FROM group_members gm JOIN groups g ON gm.group_id=g.id WHERE gm.student_id=? AND gm.group_id=? AND gm.status='pending' AND g.teacher_id=?", (uid, gid, current_user.id)).fetchone()
        if not row:
            flash('Không tìm thấy yêu cầu pending')
            return redirect('/teacher/approve_students')
        row = c.execute("SELECT email, username FROM users WHERE id=?", (uid,)).fetchone()
        email, username = row
        if action == 'approve':
            c.execute("UPDATE group_members SET status='approved' WHERE student_id=? AND group_id=?", (uid, gid))
            subject = 'Yêu cầu tham gia nhóm được chấp nhận'
            body = f"Chào {username}, yêu cầu tham gia nhóm của bạn đã được chấp nhận. Ghi chú: {note}"
        elif action == 'reject':
            c.execute("UPDATE group_members SET status='rejected', note=? WHERE student_id=? AND group_id=?", (note, uid, gid))
            subject = 'Yêu cầu tham gia nhóm bị từ chối'
            body = f"Chào {username}, yêu cầu tham gia nhóm của bạn đã bị từ chối. Ghi chú: {note}"
        conn.commit()
        # Send email
        row = c.execute("SELECT value FROM config WHERE key='mail_username'").fetchone()
        gmail_user = row[0] if row else ''
        row = c.execute("SELECT value FROM config WHERE key='mail_password'").fetchone()
        app_pass = row[0] if row else ''
        if gmail_user and app_pass:
            msg = EmailMessage()
            msg['From'] = gmail_user
            msg['To'] = email
            msg['Subject'] = subject
            msg.set_content(body)
            try:
                with smtplib.SMTP('smtp.gmail.com',587) as server:
                    server.starttls()
                    server.login(gmail_user,app_pass)
                    server.send_message(msg)
                flash('Đã gửi thông báo qua email')
            except Exception as e:
                flash(f'Gửi email thất bại: {str(e)}')
        else:
            flash('Chưa cấu hình email, không thể gửi thông báo')
        return redirect('/teacher/approve_students')
    # GET: list pending memberships in teacher's groups
    students = c.execute("""
        SELECT u.id, u.username, u.full_name, u.student_id, u.class_name, u.email, g.name, gm.group_id, gm.student_note
        FROM users u
        JOIN group_members gm ON u.id = gm.student_id
        JOIN groups g ON gm.group_id = g.id
        WHERE u.role='student' AND gm.status='pending' AND g.teacher_id=?
    """, (current_user.id,)).fetchall()
    return render_template('students.html', mode='approve', students=students)

# ----- STUDENT GROUPS MANAGEMENT -----
@app.route('/student/groups', methods=['GET','POST'])
@login_required
def student_groups():
    if current_user.role != 'student': return redirect('/dashboard')
    
    if request.method == 'POST':
        verify_csrf()
        action = request.form.get('action')
        
        if action == 'join':
            gid = request.form.get('group_id')
            note = request.form.get('student_note', '').strip()
            
            # Check if blocked
            row = c.execute("SELECT status FROM group_members WHERE student_id=? AND group_id=?", (current_user.id, gid)).fetchone()
            if row and row[0] == 'blocked':
                flash('Bạn đã bị chặn khỏi nhóm này, không thể xin tham gia lại.', 'danger')
            elif row and row[0] in ['approved', 'pending']:
                flash('Bạn đã ở trong nhóm hoặc đang chờ duyệt.', 'warning')
            else:
                # Insert or Update (if rejected/left before)
                if row:
                    c.execute("UPDATE group_members SET status='pending', student_note=?, note='' WHERE student_id=? AND group_id=?", (note, current_user.id, gid))
                else:
                    c.execute("INSERT INTO group_members(group_id, student_id, status, student_note) VALUES (?,?,'pending',?)", (gid, current_user.id, note))
                conn.commit()
                flash('Đã gửi yêu cầu tham gia nhóm!', 'success')
                
        elif action == 'leave':
            gid = request.form.get('group_id')
            # Get teacher email to notify
            row = c.execute("""
                SELECT u.email, u.username, g.name 
                FROM groups g 
                JOIN users u ON g.teacher_id = u.id 
                WHERE g.id=?
            """, (gid,)).fetchone()
            
            if row:
                teacher_email, teacher_name, group_name = row
                c.execute("UPDATE group_members SET status='left' WHERE student_id=? AND group_id=?", (current_user.id, gid))
                conn.commit()
                flash(f'Đã rời khỏi nhóm {group_name}', 'warning')
                
                # Send email to teacher
                row_conf = c.execute("SELECT value FROM config WHERE key='mail_username'").fetchone()
                gmail_user = row_conf[0] if row_conf else ''
                row_conf = c.execute("SELECT value FROM config WHERE key='mail_password'").fetchone()
                app_pass = row_conf[0] if row_conf else ''
                
                if gmail_user and app_pass and teacher_email:
                    try:
                        msg = EmailMessage()
                        msg['From'] = gmail_user
                        msg['To'] = teacher_email
                        msg['Subject'] = f'[Thông báo] Sinh viên rời nhóm {group_name}'
                        msg.set_content(f"Chào {teacher_name},\n\nSinh viên {current_user.full_name} ({current_user.username}) đã tự động rời khỏi nhóm {group_name}.\nBạn có thể thêm lại sinh viên này trong phần Quản lý sinh viên.")
                        
                        with smtplib.SMTP('smtp.gmail.com',587) as server:
                            server.starttls()
                            server.login(gmail_user,app_pass)
                            server.send_message(msg)
                    except:
                        pass # Fail silently for email
            
        return redirect('/student/groups')

    # GET: List all groups available vs joined
    # 1. My Groups (Approved)
    my_groups = c.execute("""
        SELECT g.id, g.name, u.username as teacher_name, g.description
        FROM groups g
        JOIN group_members gm ON g.id = gm.group_id
        JOIN users u ON g.teacher_id = u.id
        WHERE gm.student_id=? AND gm.status='approved'
    """, (current_user.id,)).fetchall()
    
    # 2. Pending Requests
    pending_groups = c.execute("""
        SELECT g.id, g.name, u.username, gm.student_note
        FROM groups g
        JOIN group_members gm ON g.id = gm.group_id
        JOIN users u ON g.teacher_id = u.id
        WHERE gm.student_id=? AND gm.status='pending'
    """, (current_user.id,)).fetchall()
    
    # 3. Available Groups (Not joined, not pending, not blocked)
    # Logic: Get all groups, exclude ones where user has status approved/pending/blocked
    all_groups = c.execute("SELECT g.id, g.name, u.full_name, g.description, g.code FROM groups g JOIN users u ON g.teacher_id=u.id").fetchall()
    
    available_groups = []
    for g in all_groups:
        gid = g[0]
        status_row = c.execute("SELECT status FROM group_members WHERE group_id=? AND student_id=?", (gid, current_user.id)).fetchone()
        status = status_row[0] if status_row else None
        
        if status not in ['approved', 'pending', 'blocked']:
            available_groups.append(g)

    # 4. History Groups (Left)
    history_groups = c.execute("""
        SELECT g.id, g.name, u.full_name as teacher_name, g.description
        FROM groups g
        JOIN group_members gm ON g.id = gm.group_id
        JOIN users u ON g.teacher_id = u.id
        WHERE gm.student_id=? AND gm.status='left'
    """, (current_user.id,)).fetchall()

    return render_template('student_groups.html', my_groups=my_groups, pending_groups=pending_groups, available_groups=available_groups, history_groups=history_groups)


@app.route('/student/group/<int:gid>')
@login_required
def student_group_detail(gid):
    if current_user.role != 'student': return redirect('/dashboard')
    
    # Check membership (Allow approved OR left)
    row = c.execute("SELECT g.name, g.description, COALESCE(u.full_name, u.username) FROM groups g JOIN users u ON g.teacher_id=u.id JOIN group_members gm ON g.id=gm.group_id WHERE g.id=? AND gm.student_id=? AND gm.status IN ('approved', 'left')", (gid, current_user.id)).fetchone()
    if not row:
        flash('Bạn không phải là thành viên của nhóm này')
        return redirect('/student/groups')
    
    group_name, group_desc, teacher_name = row
    
    # Get exams for this group
    # We need to filter exams where allowed_groups contains gid
    all_exams = c.execute("SELECT id, filename, release_time, expire_time, ten_de, allowed_groups FROM exams").fetchall()
    
    group_exams = []
    now = datetime.datetime.now()
    
    for e in all_exams:
        eid, filename, release_str, expire_str, ten_de, allowed_groups = e
        if allowed_groups and str(gid) in allowed_groups.split(','):
            release_time = parse_datetime(release_str)
            expire_time = parse_datetime(expire_str)
            
            if now < release_time:
                status = 'Chưa mở'
                status_class = 'text-warning'
            elif now > expire_time:
                status = 'Đã hết hạn'
                status_class = 'text-danger'
            else:
                status = 'Đang mở'
                status_class = 'text-success'
                
            group_exams.append((eid, filename, release_time.strftime('%d/%m/%Y %H:%M'), expire_time.strftime('%d/%m/%Y %H:%M'), ten_de, status, status_class))

    return render_template('student_group_detail.html', group_name=group_name, group_desc=group_desc, teacher_name=teacher_name, exams=group_exams)


# ----- STUDENT PROFILE -----
@app.route('/profile', methods=['GET','POST'])
@login_required
def profile():
    if current_user.role not in ['student', 'teacher']:
        return redirect('/dashboard')
    
    # Chỉ cho phép xem thông tin, không cho phép sửa
    # GET
    if current_user.role == 'student':
        row = c.execute("SELECT username, email, full_name, student_id, class_name FROM users WHERE id=?", (current_user.id,)).fetchone()
    else:  # teacher
        row = c.execute("SELECT username, email, full_name, teacher_id, NULL FROM users WHERE id=?", (current_user.id,)).fetchone()
        
    return render_template('profile.html', user=row, is_teacher=(current_user.role == 'teacher'), read_only=True)

# ----- CHANGE PASSWORD -----
@app.route('/change_password', methods=['GET','POST'])
@login_required
def change_password():
    if current_user.role == 'admin':
        return redirect('/dashboard')  # Admin không thể đổi mật khẩu qua route này
    errors = []
    if request.method == 'POST':
        verify_csrf()
        old_password = request.form['old_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']
        if new_password != confirm_password:
            errors.append('❌ Mật khẩu mới và xác nhận không khớp! Vui lòng nhập lại.')
        if len(new_password) < 6:
            errors.append('❌ Mật khẩu mới phải có ít nhất 6 ký tự để đảm bảo an toàn.')
        # Kiểm tra mật khẩu cũ
        row = c.execute("SELECT password, salt FROM users WHERE id=?", (current_user.id,)).fetchone()
        if not row or not check_password_hash(row[0], old_password + row[1]):
            errors.append('❌ Mật khẩu cũ không đúng! Vui lòng kiểm tra lại.')
        # Kiểm tra mật khẩu mới không được trùng mật khẩu cũ
        if row and check_password_hash(row[0], new_password + row[1]):
            errors.append('❌ Mật khẩu mới không được trùng với mật khẩu cũ! Vui lòng nhập mật khẩu khác.')
        
        if not errors:
            # Cập nhật mật khẩu mới
            new_salt = os.urandom(16).hex()
            new_hashed = generate_password_hash(new_password + new_salt)
            c.execute("UPDATE users SET password=?, salt=? WHERE id=?", (new_hashed, new_salt, current_user.id))
            conn.commit()
            return render_template('change_password.html', success_msg='Đổi mật khẩu thành công!', errors=errors)
    return render_template('change_password.html', errors=errors)

# ----- ADMIN CONFIG -----
@app.route('/admin/config', methods=['GET','POST'])
@login_required
def admin_config():
    if current_user.role!='teacher': return redirect('/dashboard')
    if request.method=='POST':
        verify_csrf()
        for key in ['mail_username','mail_password','school_name','default_release_offset','default_expire_minutes','default_subject']:
            val = request.form.get(key,'').strip()
            c.execute("REPLACE INTO config(key,value) VALUES (?,?)",(key,val))
        conn.commit()
        flash('Lưu cấu hình thành công!','success')
        return redirect('/admin/config')
    config={}
    for key in ['mail_username','mail_password','school_name','default_release_offset','default_expire_minutes','default_subject']:
        row = c.execute("SELECT value FROM config WHERE key=?",(key,)).fetchone()
        config[key] = row[0] if row else ''
    return render_template('admin_config.html', config=config)

# ----- CREATE GROUP (TEACHER) -----
@app.route('/create_group', methods=['GET','POST'])
@login_required
def create_group():
    if current_user.role != 'teacher':
        return redirect('/dashboard')
    if request.method == 'POST':
        verify_csrf()
        name = request.form['name'].strip()
        description = request.form.get('description', '').strip()
        if not name:
            flash('Tên nhóm không được để trống')
            return render_template('groups.html', mode='create')
        import string, random
        code = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
        # Không còn dùng aes_key nhóm -> lưu NULL
        c.execute("INSERT INTO groups(name, teacher_id, description, aes_key, code) VALUES (?,?,?,?,?)",
                  (name, current_user.id, description, None, code))
        conn.commit()
        flash(f'Tạo nhóm thành công! Mã nhóm: {code}')
        return redirect('/manage_groups')
    return render_template('groups.html', mode='create')

# ----- MANAGE GROUPS (TEACHER) -----
@app.route('/manage_groups')
@login_required
def manage_groups():
    if current_user.role != 'teacher':
        return redirect('/dashboard')
    groups = c.execute("SELECT id, name, description, code FROM groups WHERE teacher_id=?", (current_user.id,)).fetchall()
    return render_template('groups.html', mode='list', groups=groups)

# Đã bỏ toàn bộ chức năng bài viết và bình luận.

# ----- ADD STUDENTS TO GROUP (TEACHER) -----
@app.route('/add_students_to_group/<int:gid>', methods=['GET','POST'])
@login_required
def add_students_to_group(gid):
    if current_user.role != 'teacher':
        return redirect('/dashboard')
    # Check if group belongs to teacher
    group = c.execute("SELECT name FROM groups WHERE id=? AND teacher_id=?", (gid, current_user.id)).fetchone()
    if not group:
        flash('Không có quyền truy cập nhóm này')
        return redirect('/manage_groups')
    group_name = group[0]
    if request.method == 'POST':
        verify_csrf()
        selected_students = request.form.getlist('students')  # list of student ids
        for sid in selected_students:
            # Check if not already in group
            if not c.execute("SELECT 1 FROM group_members WHERE group_id=? AND student_id=?", (gid, sid)).fetchone():
                # Giáo viên chủ động thêm -> Auto Approved
                c.execute("INSERT INTO group_members(group_id, student_id, status) VALUES (?,?, 'approved')", (gid, sid))
        conn.commit()
        flash('Đã thêm sinh viên vào nhóm!')
        return redirect(url_for('manage_groups'))
    # GET: list students not in this group
    students = c.execute("""
        SELECT u.id, u.username, u.full_name, u.student_id, u.class_name
        FROM users u
        WHERE u.role='student' AND u.status='approved'
        AND u.id NOT IN (SELECT student_id FROM group_members WHERE group_id=?)
    """, (gid,)).fetchall()
    return render_template('groups.html', mode='add_students', group_name=group_name, gid=gid, students=students)

# ----- MANAGE STUDENTS (TEACHER) -----
@app.route('/manage_students', methods=['GET','POST'])
@login_required
def manage_students():
    if current_user.role != 'teacher':
        return redirect('/dashboard')
    if request.method == 'POST':
        verify_csrf()
        action = request.form.get('action')
        uid = request.form.get('user_id')
        gid = request.form.get('group_id')
        if action == 'remove_from_group':
            # Remove student from SPECIFIC group
            c.execute("""
                DELETE FROM group_members 
                WHERE student_id=? AND group_id=?
                AND group_id IN (SELECT id FROM groups WHERE teacher_id=?)
            """, (uid, gid, current_user.id))
            conn.commit()
            flash('Đã xoá sinh viên khỏi nhóm')
        elif action == 'add_back':
            c.execute("UPDATE group_members SET status='approved' WHERE student_id=? AND group_id=?", (uid, gid))
            conn.commit()
            flash('Đã thêm lại sinh viên vào nhóm')
        elif action == 'block':
            c.execute("UPDATE group_members SET status='blocked' WHERE student_id=? AND group_id=?", (uid, gid))
            conn.commit()
            flash('Đã chặn sinh viên khỏi nhóm')
            
        return redirect('/manage_students')

    # GET: list students in teacher's groups (individual memberships)
    # Show all students regardless of status
    students = c.execute("""
        SELECT u.id, u.username, u.full_name, u.student_id, u.class_name, u.email, g.name, g.id, gm.status
        FROM users u
        JOIN group_members gm ON u.id = gm.student_id
        JOIN groups g ON gm.group_id = g.id
        WHERE u.role='student' AND g.teacher_id=?
        ORDER BY g.name, u.username
    """, (current_user.id,)).fetchall()
    
    # Group students by group_id
    group_data = {}
    for student in students:
        gid = student[7]
        gname = student[6]
        if gid not in group_data:
            group_data[gid] = {'name': gname, 'students': []}
        # student format: (id, username, full_name, student_id, class_name, email, group_name, group_id, status)
        # Convert to format expected by template: (id, username, full_name, student_id, class_name, status)
        group_data[gid]['students'].append((student[0], student[1], student[2], student[3], student[4], student[8]))
    
    return render_template('students.html', mode='manage', group_data=group_data)

# Đã bỏ /security_info để tập trung vào luồng chính.

# ----- ADMIN USERS -----
@app.route('/admin/users', methods=['GET','POST'])
@login_required
def admin_users():
    if current_user.role != 'admin':
        return redirect('/dashboard')
    errors = []
    success_msg = None
    if request.method == 'POST':
        verify_csrf()
        action = request.form.get('action')
        if action == 'add':
            u = request.form['username'].strip()
            p = request.form['password']
            r = request.form['role']
            e = request.form['email'].strip().lower()
            full_name = request.form.get('full_name', '').strip()
            student_id = request.form.get('student_id', '').strip()
            teacher_id = request.form.get('teacher_id', '').strip()
            class_name = request.form.get('class_name', '').strip()
            
            if len(p) < 6: 
                errors.append('Mật khẩu phải ≥6 ký tự')
            if r not in ['teacher', 'student', 'admin']: 
                errors.append('Role sai')
            if c.execute("SELECT 1 FROM users WHERE username=? AND is_deleted=0", (u,)).fetchone(): 
                errors.append('Username tồn tại')
            if c.execute("SELECT 1 FROM users WHERE email=? AND is_deleted=0", (e,)).fetchone(): 
                errors.append('Email tồn tại')
            
            # Validation logic for roles
            if r == 'student':
                if not student_id:
                    errors.append('Vui lòng nhập Mã sinh viên cho tài khoản Sinh viên')
                if teacher_id:
                    errors.append('Tài khoản Sinh viên không được nhập Mã giáo viên')
            elif r == 'teacher':
                if not teacher_id:
                    errors.append('Vui lòng nhập Mã giáo viên cho tài khoản Giáo viên')
                if student_id:
                    errors.append('Tài khoản Giáo viên không được nhập Mã sinh viên')
            
            if not errors:
                salt = os.urandom(16).hex()
                hashed = generate_password_hash(p + salt)
                private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
                pem = private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.BestAvailableEncryption(b'passphrase_default')
                )
                c.execute("INSERT INTO users(username,password,role,email,rsa_private,salt,full_name,student_id,teacher_id,class_name) VALUES (?,?,?,?,?,?,?,?,?,?)",
                          (u, hashed, r, e, pem, salt, full_name, student_id, teacher_id, class_name))
                conn.commit()
                success_msg = 'Thêm user thành công!'
        
        # GET: list users with search
        search = request.args.get('search', '').strip()
        query = "SELECT id, username, role, email, full_name, student_id, teacher_id, class_name, is_locked FROM users WHERE is_deleted=0"
        params = []
        if search:
            query += " AND (username LIKE ? OR full_name LIKE ? OR email LIKE ?)"
            params = [f'%{search}%'] * 3
        users = c.execute(query, params).fetchall()
        return render_template('admin_users.html', users=users, search=search, errors=errors, success_msg=success_msg)
    
    # GET: list users with search
    search = request.args.get('search', '').strip()
    query = "SELECT id, username, role, email, full_name, student_id, teacher_id, class_name, is_locked FROM users WHERE is_deleted=0"
    params = []
    if search:
        query += " AND (username LIKE ? OR full_name LIKE ? OR email LIKE ?)"
        params = [f'%{search}%'] * 3
    users = c.execute(query, params).fetchall()
    return render_template('admin_users.html', users=users, search=search, errors=errors)

# ----- ADMIN LOCK/UNLOCK USER -----
@app.route('/admin/lock_user/<int:uid>', methods=['POST'])
@login_required
def lock_user(uid):
    if current_user.role != 'admin':
        return redirect('/dashboard')
    verify_csrf()
    errors = []
    success_msg = None
    if uid == current_user.id:
        errors.append('⚠️ Không thể khóa tài khoản của chính mình!')
    else:
        c.execute("UPDATE users SET is_locked=1 WHERE id=?", (uid,))
        conn.commit()
        success_msg = '🔒 Đã khóa tài khoản người dùng thành công! Người dùng này không thể đăng nhập nữa.'
    
    # Render lại trang với thông báo
    search = request.args.get('search', '').strip()
    query = "SELECT id, username, role, email, full_name, student_id, teacher_id, class_name, is_locked FROM users WHERE is_deleted=0"
    params = []
    if search:
        query += " AND (username LIKE ? OR full_name LIKE ? OR email LIKE ?)"
        params = [f'%{search}%'] * 3
    users = c.execute(query, params).fetchall()
    return render_template('admin_users.html', users=users, search=search, errors=errors, success_msg=success_msg)

@app.route('/admin/unlock_user/<int:uid>', methods=['POST'])
@login_required
def unlock_user(uid):
    if current_user.role != 'admin':
        return redirect('/dashboard')
    verify_csrf()
    c.execute("UPDATE users SET is_locked=0 WHERE id=?", (uid,))
    conn.commit()
    success_msg = '🔓 Đã mở khóa tài khoản thành công! Người dùng có thể đăng nhập trở lại.'
    
    # Render lại trang với thông báo
    search = request.args.get('search', '').strip()
    query = "SELECT id, username, role, email, full_name, student_id, teacher_id, class_name, is_locked FROM users WHERE is_deleted=0"
    params = []
    if search:
        query += " AND (username LIKE ? OR full_name LIKE ? OR email LIKE ?)"
        params = [f'%{search}%'] * 3
    users = c.execute(query, params).fetchall()
    return render_template('admin_users.html', users=users, search=search, errors=[], success_msg=success_msg)

# ----- ADMIN EDIT USER -----
@app.route('/admin/edit_user/<int:uid>', methods=['GET', 'POST'])
@login_required
def admin_edit_user(uid):
    if current_user.role != 'admin':
        return redirect('/dashboard')
    
    errors = []
    success_msg = None
    user = c.execute("SELECT id, username, role, email, full_name, student_id, teacher_id, class_name FROM users WHERE id=? AND is_deleted=0", (uid,)).fetchone()
    if not user:
        # Render admin_users với lỗi
        errors.append('❌ Không tìm thấy người dùng! Có thể đã bị xóa.')
        search = request.args.get('search', '').strip()
        query = "SELECT id, username, role, email, full_name, student_id, teacher_id, class_name, is_locked FROM users WHERE is_deleted=0"
        params = []
        if search:
            query += " AND (username LIKE ? OR full_name LIKE ? OR email LIKE ?)"
            params = [f'%{search}%'] * 3
        users = c.execute(query, params).fetchall()
        return render_template('admin_users.html', users=users, search=search, errors=errors, success_msg=None)
    
    if request.method == 'POST':
        verify_csrf()
        email = request.form['email'].strip().lower()
        full_name = request.form.get('full_name', '').strip()
        student_id = request.form.get('student_id', '').strip()
        teacher_id = request.form.get('teacher_id', '').strip()
        class_name = request.form.get('class_name', '').strip()
        role = user[2]  # Get current role
        
        # Check email uniqueness
        existing = c.execute("SELECT id FROM users WHERE email=? AND is_deleted=0 AND id!=?", (email, uid)).fetchone()
        if existing:
            errors.append('Email đã tồn tại')
        
        # Validation based on role
        if role == 'student':
            if not student_id:
                errors.append('Vui lòng nhập Mã sinh viên')
            if teacher_id:
                errors.append('Tài khoản Sinh viên không được có Mã giáo viên')
        elif role == 'teacher':
            if not teacher_id:
                errors.append('Vui lòng nhập Mã giáo viên')
            if student_id:
                errors.append('Tài khoản Giáo viên không được có Mã sinh viên')
        
        if not errors:
            c.execute("UPDATE users SET email=?, full_name=?, student_id=?, teacher_id=?, class_name=? WHERE id=?",
                     (email, full_name, student_id, teacher_id, class_name, uid))
            conn.commit()
            success_msg = '✅ Cập nhật thông tin người dùng thành công!'
            # Lấy lại thông tin user đã update
            user = c.execute("SELECT id, username, role, email, full_name, student_id, teacher_id, class_name FROM users WHERE id=? AND is_deleted=0", (uid,)).fetchone()
    
    return render_template('edit_user.html', user=user, errors=errors, success_msg=success_msg)

@app.route('/preview_encrypted/<int:eid>')
@login_required
def preview_encrypted(eid):
    row = c.execute("SELECT enc_path, filename, allowed_students, release_time, expire_time FROM exams WHERE id=?", (eid,)).fetchone()
    if not row: return "Lỗi: Không tìm thấy file"
    enc_path, filename, allowed, release_time_str, expire_time_str = row
    
    # Check permissions
    if current_user.role == 'student':
        if allowed and current_user.username not in allowed.split(','):
            return "Lỗi: Không có quyền truy cập"
            
    try:
        if not os.path.exists(enc_path): return "File không tồn tại trên server"
        
        with open(enc_path, 'rb') as f:
            b64_data = f.read()
        
        output = []
        output.append(f"FILE: {filename}")
        output.append(f"PATH: {enc_path}")
        output.append(f"SIZE: {os.path.getsize(enc_path)} bytes")
        output.append(f"ALGORITHM: AES-256-GCM (Stored as Base64)")
        output.append("-" * 80)
        output.append("FILE CONTENT (Base64)")
        output.append("-" * 80)
        
        b64_str = b64_data.decode('utf-8')
        
        # Break into lines of 80 chars
        for i in range(0, len(b64_str), 80):
            output.append(b64_str[i:i+80])
            
        if os.path.getsize(enc_path) > 1024:
            output.append("...")
            output.append(f"(... {os.path.getsize(enc_path) - 1024} bytes remaining ...)")
            
        joined = '\n'.join(output)
        return f"<pre>{joined}</pre>"
    except Exception as e:
        return f"Error reading file: {str(e)}"

@app.route('/tamper_exam/<int:eid>')
@login_required
def tamper_exam(eid):
    if current_user.role != 'teacher': return redirect('/dashboard')
    
    # Lấy đường dẫn file
    row = c.execute("SELECT enc_path, filename FROM exams WHERE id=?", (eid,)).fetchone()
    if not row:
        flash('Không tìm thấy đề thi')
        return redirect('/dashboard')
    
    enc_path, filename = row
    
    try:
        if not os.path.exists(enc_path):
            flash('File không tồn tại')
            return redirect('/dashboard')
            
        # Đọc file Base64, decode, sửa 1 byte, encode lại
        with open(enc_path, 'rb') as f:
            b64_data = f.read()
        
        data = bytearray(base64.b64decode(b64_data))
        
        if len(data) > 50:
            pos = int(len(data) / 2)
            old_byte = data[pos]
            new_byte = old_byte ^ 0xFF
            data[pos] = new_byte
            
            # Write back
            with open(enc_path, 'wb') as f:
                f.write(base64.b64encode(data))
                
            msg = f"""
            <strong><i class="fas fa-check-circle"></i> Đã giả lập tấn công thành công!</strong><br>
            <ul>
                <li>File: <b>{filename}</b></li>
                <li>Vị trí thay đổi (Offset): <code>0x{pos:X}</code></li>
                <li>Giá trị cũ: <code>0x{old_byte:02X}</code></li>
                <li>Giá trị mới: <code>0x{new_byte:02X}</code></li>
            </ul>
            <em>File đã bị mất tính toàn vẹn. Hệ thống sẽ từ chối giải mã.</em>
            """
            flash(msg, 'warning')
        else:
            flash('File quá nhỏ để giả lập', 'warning')
    except Exception as e:
        flash(f'Lỗi giả lập: {str(e)}', 'danger')
        
    return redirect('/dashboard')

@app.route('/restore_exam/<int:eid>')
@login_required
def restore_exam(eid):
    if current_user.role != 'teacher': return redirect('/dashboard')
    
    # Lấy đường dẫn file
    row = c.execute("SELECT enc_path, filename FROM exams WHERE id=?", (eid,)).fetchone()
    if not row:
        flash('Không tìm thấy đề thi')
        return redirect('/dashboard')
    
    enc_path, filename = row
    
    # Logic khôi phục: Thực ra chỉ cần chạy lại hàm tạo file gốc (nếu là file demo)
    # Nhưng vì đây là file upload thật, ta không có bản backup.
    # TUY NHIÊN: Vì ta dùng phép XOR (đảo bit) để phá hoại: A ^ 0xFF = B
    # Thì B ^ 0xFF = A (đảo ngược lại sẽ về như cũ).
    # Nên ta chỉ cần gọi lại hàm tamper một lần nữa vào đúng vị trí đó là xong!
    # Nhưng để chắc ăn và đơn giản cho demo, ta sẽ dùng lại logic tamper nhưng đổi thông báo.
    
    try:
        if not os.path.exists(enc_path):
            flash('File không tồn tại')
            return redirect('/dashboard')
            
        with open(enc_path, 'rb') as f:
            b64_data = f.read()
        
        data = bytearray(base64.b64decode(b64_data))
        
        if len(data) > 50:
            pos = int(len(data) / 2)
            old_byte = data[pos]
            new_byte = old_byte ^ 0xFF
            data[pos] = new_byte
            
            with open(enc_path, 'wb') as f:
                f.write(base64.b64encode(data))
                
            msg = f"""
            <strong><i class="fas fa-tools"></i> Đã khôi phục file thành công!</strong><br>
            <ul>
                <li>File: <b>{filename}</b></li>
                <li>Vị trí sửa lại: <code>0x{pos:X}</code></li>
                <li>Giá trị đã khôi phục: <code>0x{new_byte:02X}</code></li>
            </ul>
            <em>File đã trở lại trạng thái nguyên vẹn. Có thể giải mã bình thường.</em>
            """
            flash(msg, 'success')
        else:
            flash('File quá nhỏ', 'warning')
    except Exception as e:
        flash(f'Lỗi khôi phục: {str(e)}', 'danger')
        
    return redirect('/dashboard')

@app.route('/teacher/exam_logs/<int:eid>')
@login_required
def exam_logs(eid):
    if current_user.role != 'teacher':
        return redirect('/dashboard')
    
    # Check ownership
    row = c.execute("SELECT ten_de, teacher_id FROM exams WHERE id=?", (eid,)).fetchone()
    if not row or row[1] != current_user.id:
        flash('Không có quyền truy cập')
        return redirect('/dashboard')
    
    exam_title = row[0]
    
    # Get logs
    logs = c.execute("""
        SELECT u.username, u.full_name, u.student_id, a.timestamp, a.ip_address 
        FROM audit_logs a 
        JOIN users u ON a.user_id = u.id 
        WHERE a.exam_id = ? AND a.action = 'view_exam'
        ORDER BY a.timestamp DESC
    """, (eid,)).fetchall()
    
    return render_template('exam_logs.html', logs=logs, exam_title=exam_title, eid=eid)

@app.route('/teacher/debug_exam/<int:eid>')
@login_required
def debug_exam(eid):
    if current_user.role != 'teacher': return redirect('/dashboard')
    
    # 1. Lấy thông tin từ DB
    row = c.execute("SELECT filename, enc_path, encrypted_aes_key, file_hash, signature, teacher_id FROM exams WHERE id=?", (eid,)).fetchone()
    if not row: return "Not found"
    filename, enc_path, encrypted_aes_key, file_hash, signature, teacher_id = row
    
    if teacher_id != current_user.id: return "Access Denied"

    # 2. Đọc file vật lý để tách thành phần AES-GCM
    if not os.path.exists(enc_path): return "File missing"
    
    with open(enc_path, 'rb') as f:
        file_data = base64.b64decode(f.read())
    
    # Cấu trúc file: IV (12 bytes) + Tag (16 bytes) + Ciphertext (n bytes)
    iv = file_data[:12]
    tag = file_data[12:28]
    ciphertext_sample = file_data[28:60] # Lấy mẫu 32 bytes đầu của nội dung
    
    # 3. Lấy RSA Private Key của giáo viên (đang lưu trong DB dưới dạng PEM mã hóa)
    teacher_row = c.execute("SELECT rsa_private FROM users WHERE id=?", (current_user.id,)).fetchone()
    rsa_private_pem = teacher_row[0] if teacher_row else b''
    
    # 4. Giả lập quy trình giải mã để lấy lại AES Key (Show cho thầy xem)
    recovered_aes_key = b''
    try:
        if encrypted_aes_key and rsa_private_pem:
            recovered_aes_key = rsa_decrypt_key(encrypted_aes_key, rsa_private_pem)
    except Exception as e:
        recovered_aes_key = b'Error decrypting'

    debug_info = {
        'filename': filename,
        'file_size': len(file_data),
        'iv_hex': iv.hex().upper(),
        'tag_hex': tag.hex().upper(),
        'ciphertext_sample_hex': ciphertext_sample.hex().upper(),
        'encrypted_aes_key_hex': encrypted_aes_key.hex().upper() if encrypted_aes_key else 'N/A',
        'recovered_aes_key_hex': recovered_aes_key.hex().upper() if recovered_aes_key else 'N/A',
        'rsa_private_preview': rsa_private_pem.decode('utf-8').split('\n')[1] + '...' if rsa_private_pem else 'Không có khóa RSA',
        'file_hash': file_hash,
        'signature_hex': signature.hex().upper() if signature else 'N/A'
    }
    
    return render_template('debug_exam.html', info=debug_info)

@app.route('/edit_exam/<int:eid>', methods=['GET','POST'])
@login_required
def edit_exam(eid):
    if current_user.role != 'teacher': return redirect('/dashboard')
    
    # Check ownership
    row = c.execute("SELECT ten_de, release_time, expire_time, pin_code, auth_mode, teacher_id, allowed_groups FROM exams WHERE id=?", (eid,)).fetchone()
    if not row or row[5] != current_user.id:
        flash('Không có quyền chỉnh sửa')
        return redirect('/dashboard')
    
    ten_de, release_str, expire_str, pin_code, auth_mode, _, current_allowed_groups = row
    
    # Calculate duration
    release_time = parse_datetime(release_str)
    expire_time = parse_datetime(expire_str)
    duration_minutes = int((expire_time - release_time).total_seconds() / 60)
    
    # Get names of currently allowed groups for display (Read-only)
    allowed_group_names = []
    if current_allowed_groups:
        # Safe split and filter empty
        gids = [g for g in current_allowed_groups.split(',') if g]
        if gids:
            placeholders = ','.join('?' for _ in gids)
            rows = c.execute(f"SELECT name FROM groups WHERE id IN ({placeholders})", gids).fetchall()
            allowed_group_names = [r[0] for r in rows]
    
    if request.method == 'POST':
        verify_csrf()
        new_ten_de = request.form['ten_de'].strip()
        new_release_date = request.form['release_date']
        new_release_time = request.form['release_time']
        new_duration = int(request.form.get('expire_minutes', 60))
        new_auth_mode = request.form.get('auth_mode', 'pin')
        new_pin_code = request.form.get('pin_code', '').strip()
        
        # Auto-generate PIN if missing but required by mode
        if new_auth_mode in ['pin'] and not new_pin_code:
            new_pin_code = ''.join(secrets.choice('0123456789') for _ in range(6))
        
        # Note: We DO NOT update allowed_groups or allowed_students here to prevent data corruption.
        # Changing assigned groups requires deleting and re-uploading the exam.
            
        try:
            new_release_dt = datetime.datetime.strptime(f"{new_release_date} {new_release_time}", '%Y-%m-%d %H:%M')
            new_expire_dt = new_release_dt + datetime.timedelta(minutes=new_duration)
            now = datetime.datetime.now()
            
            # Validation logic
            # Nếu đề chưa mở: cho phép thay đổi tất cả
            if now < release_time:
                if new_release_dt < now:
                    flash('❌ Thời gian mở đề không được trong quá khứ! Vui lòng chọn thời gian trong tương lai.', 'danger')
                    return redirect(url_for('edit_exam', eid=eid))
                if new_expire_dt <= new_release_dt:
                    flash('❌ Thời gian đóng đề phải sau thời gian mở đề! Vui lòng kiểm tra lại.', 'danger')
                    return redirect(url_for('edit_exam', eid=eid))
            # Nếu đề đang mở: chỉ cho phép nới rộng thời gian đóng đề
            elif now <= expire_time:
                # Không cho thay đổi thời gian mở
                new_release_dt = release_time
                # Chỉ cho phép đẩy thời gian đóng ra sau
                if new_expire_dt <= now:
                    flash('❌ Đề thi đang mở! Thới gian đóng mới phải sau thời điểm hiện tại.', 'danger')
                    return redirect(url_for('edit_exam', eid=eid))
                if new_expire_dt < expire_time:
                    flash('⚠️ Đề thi đang mở! Chỉ có thể NỚI RỘNG thời gian đóng đề (không thể rút ngắn).', 'warning')
                    return redirect(url_for('edit_exam', eid=eid))
            # Nếu đề đã hết hạn: không cho sửa
            else:
                flash('❌ Đề thi đã hết hạn! Không thể chỉnh sửa nữa.', 'danger')
                return redirect('/dashboard')
            
            c.execute("""
                UPDATE exams 
                SET ten_de=?, release_time=?, expire_time=?, pin_code=?, auth_mode=?
                WHERE id=?
            """, (new_ten_de, new_release_dt.strftime('%Y-%m-%dT%H:%M'), new_expire_dt.strftime('%Y-%m-%dT%H:%M'), new_pin_code, new_auth_mode, eid))
            conn.commit()
            flash(f'✅ Cập nhật thành công! Mở đề lúc: {new_release_dt.strftime("%d/%m/%Y %H:%M")}, Đóng lúc: {new_expire_dt.strftime("%d/%m/%Y %H:%M")}', 'success')
            return redirect('/dashboard')
        except Exception as e:
            flash(f'Lỗi cập nhật: {str(e)}', 'danger')

    exam_data = {
        'ten_de': ten_de,
        'release_date': release_time.strftime('%Y-%m-%d'),
        'release_time': release_time.strftime('%H:%M'),
        'duration_minutes': duration_minutes,
        'pin_code': pin_code,
        'auth_mode': auth_mode,
        'release_display': release_time.strftime('%d/%m/%Y %H:%M'),
        'expire_display': expire_time.strftime('%d/%m/%Y %H:%M')
    }
    
    # Check exam status
    now = datetime.datetime.now()
    if now < release_time:
        exam_status = 'upcoming'
        status_message = f'⏰ Đề thi chưa mở. Sẽ mở vào: {release_time.strftime("%d/%m/%Y %H:%M")}'
    elif now > expire_time:
        exam_status = 'expired'
        status_message = f'❌ Đề thi đã hết hạn vào: {expire_time.strftime("%d/%m/%Y %H:%M")}'
    else:
        exam_status = 'active'
        status_message = f'✅ Đề thi đang mở! Chỉ có thể nới rộng thời gian đóng đề (hiện tại: {expire_time.strftime("%d/%m/%Y %H:%M")})'
    
    return render_template('edit_exam.html', exam=exam_data, allowed_group_names=allowed_group_names, exam_status=exam_status, status_message=status_message)

@app.route('/student/teachers')
@login_required
def student_teachers():
    if current_user.role != 'student': return redirect('/dashboard')
    
    teachers = c.execute("""
        SELECT DISTINCT u.id, u.full_name, u.email, u.username
        FROM users u
        JOIN groups g ON u.id = g.teacher_id
        JOIN group_members gm ON g.id = gm.group_id
        WHERE gm.student_id = ? AND gm.status IN ('approved', 'left')
    """, (current_user.id,)).fetchall()
    
    return render_template('student_teachers.html', teachers=teachers)

@app.route('/student/teacher/<int:tid>')
@login_required
def student_teacher_detail(tid):
    if current_user.role != 'student': return redirect('/dashboard')
    
    teacher = c.execute("SELECT full_name, email FROM users WHERE id=?", (tid,)).fetchone()
    if not teacher:
        flash('Giáo viên không tồn tại')
        return redirect('/student/teachers')
        
    # Get all exams by this teacher
    all_exams = c.execute("SELECT id, filename, release_time, expire_time, ten_de, allowed_groups, allowed_students FROM exams WHERE teacher_id=?", (tid,)).fetchall()
    
    # Get student's groups (approved OR left)
    my_groups = [str(r[0]) for r in c.execute("SELECT group_id FROM group_members WHERE student_id=? AND status IN ('approved', 'left')", (current_user.id,)).fetchall()]
    
    visible_exams = []
    now = datetime.datetime.now()
    
    for e in all_exams:
        eid, filename, release_str, expire_str, ten_de, allowed_groups, allowed_students = e
        
        is_allowed = False
        # Check direct permission
        if allowed_students and current_user.username in allowed_students.split(','):
            is_allowed = True
        # Check group permission
        elif allowed_groups:
            exam_groups = allowed_groups.split(',')
            for g in exam_groups:
                if g in my_groups:
                    is_allowed = True
                    break
        
        if is_allowed:
            release_time = parse_datetime(release_str)
            expire_time = parse_datetime(expire_str)
            
            if now < release_time:
                status = 'Chưa mở'
                status_class = 'text-warning'
            elif now > expire_time:
                status = 'Đã hết hạn'
                status_class = 'text-danger'
            else:
                status = 'Đang mở'
                status_class = 'text-success'
            
            visible_exams.append((eid, filename, release_time.strftime('%d/%m/%Y %H:%M'), expire_time.strftime('%d/%m/%Y %H:%M'), ten_de, status, status_class))
            
    return render_template('student_teacher_detail.html', teacher=teacher, exams=visible_exams)

# ----- VIEW SUBMISSIONS (TEACHER) -----
@app.route('/view_submissions/<int:eid>')
@login_required
def view_submissions(eid):
    if current_user.role != 'teacher':
        return redirect('/dashboard')
    
    # Check ownership
    row = c.execute("SELECT teacher_id, ten_de FROM exams WHERE id=?", (eid,)).fetchone()
    if not row or row[0] != current_user.id:
        return "Không có quyền"
    
    exam_name = row[1]
    submissions = c.execute("""
        SELECT s.id, u.username, u.full_name, u.student_id, s.submission_time, s.filename
        FROM submissions s
        JOIN users u ON s.student_id = u.id
        WHERE s.exam_id = ?
        ORDER BY s.submission_time DESC
    """, (eid,)).fetchall()
    
    return render_template('view_submissions.html', submissions=submissions, exam_name=exam_name, eid=eid)

# ----- DOWNLOAD SUBMISSION -----
@app.route('/download_submission/<int:sid>')
@login_required
def download_submission(sid):
    row = c.execute("SELECT enc_path, filename, student_id, exam_id FROM submissions WHERE id=?", (sid,)).fetchone()
    if not row:
        return "File không tìm thấy"
    
    enc_path, filename, student_id, exam_id = row
    
    # Check permissions (student can download own, teacher can download from their exams)
    if current_user.role == 'student' and current_user.id != student_id:
        return "Không có quyền"
    elif current_user.role == 'teacher':
        exam_row = c.execute("SELECT teacher_id FROM exams WHERE id=?", (exam_id,)).fetchone()
        if not exam_row or exam_row[0] != current_user.id:
            return "Không có quyền"
    
    # Decrypt and send
    try:
        with open(enc_path, 'rb') as f:
            data = base64.b64decode(f.read())
        
        iv, tag, ct = data[:12], data[12:28], data[28:]
        
        # Get student's private key
        student_row = c.execute("SELECT rsa_private FROM users WHERE id=?", (student_id,)).fetchone()
        sub_row = c.execute("SELECT encrypted_aes_key FROM submissions WHERE id=?", (sid,)).fetchone()
        
        if student_row and sub_row:
            decrypted_aes_key = rsa_decrypt_key(sub_row[0], student_row[0])
            decryptor = Cipher(algorithms.AES(decrypted_aes_key), modes.GCM(iv, tag)).decryptor()
            decrypted = decryptor.update(ct) + decryptor.finalize()
            
            return send_file(io.BytesIO(decrypted), as_attachment=True, download_name=filename)
    except Exception as e:
        return f"Lỗi giải mã: {str(e)}"

# ----- VIEW SUBMISSION (TEACHER) - View PDF in browser -----
@app.route('/view_submission/<int:sid>')
@login_required
def view_submission(sid):
    row = c.execute("SELECT enc_path, filename, student_id, exam_id FROM submissions WHERE id=?", (sid,)).fetchone()
    if not row:
        return "File không tìm thấy"
    
    enc_path, filename, student_id, exam_id = row
    
    # Check permissions - only teacher can view
    if current_user.role != 'teacher':
        return "Không có quyền"
    
    exam_row = c.execute("SELECT teacher_id FROM exams WHERE id=?", (exam_id,)).fetchone()
    if not exam_row or exam_row[0] != current_user.id:
        return "Không có quyền"
    
    # Decrypt and send as inline PDF
    try:
        with open(enc_path, 'rb') as f:
            data = base64.b64decode(f.read())
        
        iv, tag, ct = data[:12], data[12:28], data[28:]
        
        # Get student's private key
        student_row = c.execute("SELECT rsa_private FROM users WHERE id=?", (student_id,)).fetchone()
        sub_row = c.execute("SELECT encrypted_aes_key FROM submissions WHERE id=?", (sid,)).fetchone()
        
        if student_row and sub_row:
            decrypted_aes_key = rsa_decrypt_key(sub_row[0], student_row[0])
            decryptor = Cipher(algorithms.AES(decrypted_aes_key), modes.GCM(iv, tag)).decryptor()
            decrypted = decryptor.update(ct) + decryptor.finalize()
            
            # Send as inline (display in browser)
            return send_file(io.BytesIO(decrypted), mimetype='application/pdf', as_attachment=False, download_name=filename)
    except Exception as e:
        return f"Lỗi giải mã: {str(e)}"

# ----- SUBMIT EXAM (STUDENT) -----
@app.route('/submit_exam/<int:eid>', methods=['GET', 'POST'])
@login_required
def submit_exam(eid):
    if current_user.role != 'student':
        return redirect('/dashboard')
    
    # Get exam info
    exam = c.execute("SELECT id, ten_de, release_time, expire_time, teacher_id, allowed_groups FROM exams WHERE id=?", (eid,)).fetchone()
    if not exam:
        flash('❌ Không tìm thấy đề thi!', 'danger')
        return redirect('/dashboard')
    
    exam_id, ten_de, release_str, expire_str, teacher_id, allowed_groups = exam
    release_time = parse_datetime(release_str)
    expire_time = parse_datetime(expire_str)
    now = datetime.datetime.now()
    
    # Check permissions
    if allowed_groups:
        student_groups = c.execute("SELECT group_id FROM group_members WHERE student_id=? AND status='approved'", (current_user.id,)).fetchall()
        student_group_ids = [str(g[0]) for g in student_groups]
        exam_group_ids = allowed_groups.split(',')
        has_permission = any(gid in student_group_ids for gid in exam_group_ids)
        if not has_permission:
            flash('🔒 Bạn không có quyền nộp bài cho đề thi này!', 'danger')
            return redirect('/dashboard')
    
    # Check time
    if now < release_time:
        flash(f'⏰ Đề thi chưa mở! Sẽ mở lúc: {release_time.strftime("%d/%m/%Y %H:%M")}', 'warning')
        return redirect('/dashboard')
    
    if now > expire_time:
        flash('⏰ Đã hết thời gian nộp bài!', 'danger')
        return redirect('/dashboard')
    
    # Check existing submission
    existing = c.execute("SELECT id, filename, submission_time, score, teacher_note FROM submissions WHERE exam_id=? AND student_id=?", (eid, current_user.id)).fetchone()
    
    errors = []
    success_msg = None
    
    if request.method == 'POST':
        verify_csrf()
        
        # Check time again
        if now > expire_time:
            errors.append('⏰ Đã hết thời gian nộp bài!')
            return render_template('submit_exam.html', exam={'id': exam_id, 'ten_de': ten_de, 'expire_time': expire_time}, existing=existing, errors=errors, success_msg=success_msg)
        
        if 'file' not in request.files or not request.files['file'].filename:
            errors.append('❌ Vui lòng chọn file để nộp!')
            return render_template('submit_exam.html', exam={'id': exam_id, 'ten_de': ten_de, 'expire_time': expire_time}, existing=existing, errors=errors, success_msg=success_msg)
        
        file = request.files['file']
        
        # Check PDF
        if not file.filename.lower().endswith('.pdf') or file.mimetype != 'application/pdf':
            errors.append('📄 Chỉ chấp nhận file định dạng PDF!')
            return render_template('submit_exam.html', exam={'id': exam_id, 'ten_de': ten_de, 'expire_time': expire_time}, existing=existing, errors=errors, success_msg=success_msg)
        
        filename = secure_filename(file.filename)
        raw_data = file.read()
        
        # Hash file
        file_hash = hash_file(raw_data)
        
        # AES-256-GCM Encryption
        aes_key = os.urandom(32)
        iv = os.urandom(12)
        encryptor = Cipher(algorithms.AES(aes_key), modes.GCM(iv)).encryptor()
        ct = encryptor.update(raw_data) + encryptor.finalize()
        tag = encryptor.tag
        
        # Save encrypted file
        enc_filename = f"submission_{current_user.id}_{eid}_{filename}"
        enc_path = os.path.join(app.config['UPLOAD_FOLDER'], enc_filename)
        with open(enc_path, 'wb') as f:
            f.write(base64.b64encode(iv + tag + ct))
        
        # RSA wrap AES key using student's private key
        student_row = c.execute("SELECT rsa_private FROM users WHERE id=?", (current_user.id,)).fetchone()
        student_private_key = student_row[0] if student_row and student_row[0] else None
        
        # Generate RSA key if student doesn't have one
        if not student_private_key:
            private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.BestAvailableEncryption(b'passphrase_default')
            )
            c.execute("UPDATE users SET rsa_private=? WHERE id=?", (pem, current_user.id))
            conn.commit()
            student_private_key = pem
        
        encrypted_aes_key = rsa_encrypt_key(aes_key, student_private_key)
        
        submission_time = now.strftime('%Y-%m-%dT%H:%M:%S')
        
        # Update or insert submission
        if existing:
            # Delete old file
            if existing and len(existing) > 0:
                old_sub = c.execute("SELECT enc_path FROM submissions WHERE id=?", (existing[0],)).fetchone()
                if old_sub and os.path.exists(old_sub[0]):
                    os.remove(old_sub[0])
            
            c.execute("""UPDATE submissions 
                        SET filename=?, enc_path=?, submission_time=?, encrypted_aes_key=?, file_hash=?, score=NULL, teacher_note=NULL, graded_time=NULL
                        WHERE exam_id=? AND student_id=?""",
                     (filename, enc_path, submission_time, encrypted_aes_key, file_hash, eid, current_user.id))
            success_msg = '✅ Đã cập nhật bài nộp thành công!'
        else:
            c.execute("""INSERT INTO submissions(exam_id, student_id, filename, enc_path, submission_time, encrypted_aes_key, file_hash)
                        VALUES (?,?,?,?,?,?,?)""",
                     (eid, current_user.id, filename, enc_path, submission_time, encrypted_aes_key, file_hash))
            success_msg = '✅ Nộp bài thành công!'
        
        conn.commit()
        
        # Refresh existing data
        existing = c.execute("SELECT id, filename, submission_time, score, teacher_note FROM submissions WHERE exam_id=? AND student_id=?", (eid, current_user.id)).fetchone()
    
    # Calculate time remaining
    time_remaining = (expire_time - now).total_seconds()
    
    return render_template('submit_exam.html', 
                          exam={'id': exam_id, 'ten_de': ten_de, 'expire_time': expire_time, 'time_remaining': time_remaining},
                          existing=existing, 
                          errors=errors, 
                          success_msg=success_msg)

# ----- MANAGE SUBMISSIONS (TEACHER) -----
@app.route('/teacher/submissions/<int:eid>')
@login_required
def teacher_submissions(eid):
    if current_user.role != 'teacher':
        return redirect('/dashboard')
    
    # Check ownership
    exam = c.execute("SELECT id, ten_de, teacher_id FROM exams WHERE id=?", (eid,)).fetchone()
    if not exam or exam[2] != current_user.id:
        flash('❌ Không có quyền truy cập!', 'danger')
        return redirect('/dashboard')
    
    # Get all submissions for this exam
    submissions = c.execute("""
        SELECT s.id, u.username, u.full_name, u.student_id, s.filename, s.submission_time, s.score, s.teacher_note, s.graded_time
        FROM submissions s
        JOIN users u ON s.student_id = u.id
        WHERE s.exam_id = ?
        ORDER BY s.submission_time DESC
    """, (eid,)).fetchall()
    
    return render_template('teacher_submissions.html', exam={'id': exam[0], 'ten_de': exam[1]}, submissions=submissions)

# ----- GRADE SUBMISSION (TEACHER) -----
@app.route('/teacher/grade_submission/<int:sid>', methods=['GET', 'POST'])
@login_required
def grade_submission(sid):
    if current_user.role != 'teacher':
        return redirect('/dashboard')
    
    # Get submission info
    submission = c.execute("""
        SELECT s.id, s.exam_id, s.student_id, s.filename, s.submission_time, s.score, s.teacher_note,
               u.username, u.full_name, u.student_id as student_code,
               e.ten_de, e.teacher_id
        FROM submissions s
        JOIN users u ON s.student_id = u.id
        JOIN exams e ON s.exam_id = e.id
        WHERE s.id = ?
    """, (sid,)).fetchone()
    
    if not submission:
        flash('❌ Không tìm thấy bài nộp!', 'danger')
        return redirect('/dashboard')
    
    # Check ownership
    if submission[11] != current_user.id:
        flash('❌ Không có quyền chấm điểm!', 'danger')
        return redirect('/dashboard')
    
    errors = []
    success_msg = None
    
    if request.method == 'POST':
        verify_csrf()
        score = request.form.get('score', '').strip()
        teacher_note = request.form.get('teacher_note', '').strip()
        
        # Validate score
        try:
            score_float = float(score) if score else None
            if score_float is not None and (score_float < 0 or score_float > 10):
                errors.append('❌ Điểm phải từ 0 đến 10!')
        except:
            errors.append('❌ Điểm không hợp lệ!')
        
        if not errors:
            graded_time = datetime.datetime.now().strftime('%Y-%m-%dT%H:%M:%S')
            c.execute("""UPDATE submissions 
                        SET score=?, teacher_note=?, graded_time=?
                        WHERE id=?""",
                     (score_float, teacher_note, graded_time, sid))
            conn.commit()
            success_msg = '✅ Đã lưu điểm thành công!'
            
            # Refresh submission data
            submission = c.execute("""
                SELECT s.id, s.exam_id, s.student_id, s.filename, s.submission_time, s.score, s.teacher_note,
                       u.username, u.full_name, u.student_id as student_code,
                       e.ten_de, e.teacher_id
                FROM submissions s
                JOIN users u ON s.student_id = u.id
                JOIN exams e ON s.exam_id = e.id
                WHERE s.id = ?
            """, (sid,)).fetchone()
    
    return render_template('grade_submission.html', submission=submission, errors=errors, success_msg=success_msg)

# ----- VIEW SUBMISSION (STUDENT) -----
@app.route('/student/my_submissions')
@login_required
def student_submissions():
    if current_user.role != 'student':
        return redirect('/dashboard')
    
    # Get all submissions by this student
    submissions = c.execute("""
        SELECT s.id, e.ten_de, s.filename, s.submission_time, s.score, s.teacher_note, s.graded_time, e.id as exam_id
        FROM submissions s
        JOIN exams e ON s.exam_id = e.id
        WHERE s.student_id = ?
        ORDER BY s.submission_time DESC
    """, (current_user.id,)).fetchall()
    
    return render_template('student_submissions.html', submissions=submissions)

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True, port=5000)

