import sqlite3
import os
import datetime
from werkzeug.security import generate_password_hash
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import random
import string

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
import io

# --- CONFIG ---
DB_FILE = 'exam.db'
UPLOAD_FOLDER = 'uploads'
NUM_TEACHERS = 2
NUM_STUDENTS = 10
NUM_GROUPS_PER_TEACHER = 2
NUM_EXAMS_PER_TEACHER = 3

# --- HELPERS ---
def generate_rsa_key_pem():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(b'passphrase_default')
    )

def create_real_pdf_content(filename):
    """Create a valid PDF file in memory using reportlab"""
    buffer = io.BytesIO()
    c = canvas.Canvas(buffer, pagesize=letter)
    c.drawString(100, 750, f"DE THI MAU: {filename}")
    c.drawString(100, 730, "Day la noi dung de thi duoc tao tu dong.")
    c.drawString(100, 710, "Noi dung nay dung de demo tinh nang ma hoa va giai ma.")
    c.drawString(100, 690, f"Thoi gian tao: {datetime.datetime.now()}")
    c.save()
    buffer.seek(0)
    return buffer.read()

def encrypt_and_save_file(filename, aes_key):
    """Encrypt PDF content with AES-GCM and save to disk"""
    raw_data = create_real_pdf_content(filename)
    
    # Calculate hash of original file
    digest = hashes.Hash(hashes.SHA256())
    digest.update(raw_data)
    file_hash = digest.finalize().hex()

    # Encrypt
    iv = os.urandom(12)
    encryptor = Cipher(algorithms.AES(aes_key), modes.GCM(iv)).encryptor()
    ct = encryptor.update(raw_data) + encryptor.finalize()
    tag = encryptor.tag

    enc_path = os.path.join(UPLOAD_FOLDER, f"enc_{filename}")
    with open(enc_path, 'wb') as f:
        f.write(iv + tag + ct)
    
    return enc_path, file_hash

def rsa_encrypt_key(aes_key, private_key_pem):
    private_key = serialization.load_pem_private_key(private_key_pem, password=b'passphrase_default')
    public_key = private_key.public_key()
    return public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def sign_data(data, private_key_pem):
    private_key = serialization.load_pem_private_key(private_key_pem, password=b'passphrase_default')
    return private_key.sign(
        data,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )

# --- MAIN SEEDING LOGIC ---
def seed_database():
    if os.path.exists(DB_FILE):
        print("Database file exists. Deleting to create a fresh one.")
        os.remove(DB_FILE)

    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()

    # Re-run table creation from app.py
    print("Creating tables...")
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password TEXT, role TEXT, email TEXT UNIQUE, rsa_private BLOB, salt TEXT, full_name TEXT, student_id TEXT, class_name TEXT, status TEXT DEFAULT 'approved', approval_note TEXT, selected_teachers TEXT, teacher_id TEXT, failed_attempts INTEGER DEFAULT 0, lock_until TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS exams
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, filename TEXT, enc_path TEXT, release_time TEXT, expire_time TEXT, teacher_id INTEGER, ten_de TEXT, aes_key BLOB, encrypted_aes_key BLOB, allowed_students TEXT DEFAULT '', signature BLOB, file_hash TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS groups
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, teacher_id INTEGER, description TEXT, aes_key BLOB, code TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS group_members
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, group_id INTEGER, student_id INTEGER, status TEXT DEFAULT 'pending')''')
    c.execute('''CREATE TABLE IF NOT EXISTS audit_logs
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, exam_id INTEGER, action TEXT, timestamp TEXT, ip_address TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS config (id INTEGER PRIMARY KEY AUTOINCREMENT, key TEXT UNIQUE, value TEXT)''')
    for k, v in [('mail_username',''),('mail_password',''),('school_name','Trường Đại học Sài Gòn'), ('default_release_offset','1'), ('default_expire_minutes','120'), ('default_subject','')]:
        c.execute("INSERT OR IGNORE INTO config(key,value) VALUES (?,?)",(k,v))
    conn.commit()

    # 1. Create Admin
    print("Creating admin user...")
    salt = os.urandom(16).hex()
    hashed_pw = generate_password_hash('admin123' + salt)
    c.execute("INSERT INTO users(username, password, role, email, rsa_private, salt, full_name) VALUES (?,?,?,?,?,?,?)",
              ('admin', hashed_pw, 'admin', 'admin@school.com', generate_rsa_key_pem(), salt, 'Administrator'))
    
    # 2. Create Teachers
    print(f"Creating {NUM_TEACHERS} teacher users...")
    teacher_ids = []
    for i in range(1, NUM_TEACHERS + 1):
        username = f'teacher{i}'
        salt = os.urandom(16).hex()
        hashed_pw = generate_password_hash('password123' + salt)
        teacher_id = c.execute("INSERT INTO users(username, password, role, email, rsa_private, salt, full_name, teacher_id) VALUES (?,?,?,?,?,?,?,?)",
                               (username, hashed_pw, 'teacher', f'{username}@school.com', generate_rsa_key_pem(), salt, f'Giáo viên {i}', f'GV00{i}')).lastrowid
        teacher_ids.append(teacher_id)

    # 3. Create Students
    print(f"Creating {NUM_STUDENTS} student users...")
    student_ids = []
    for i in range(1, NUM_STUDENTS + 1):
        username = f'student{i}'
        salt = os.urandom(16).hex()
        hashed_pw = generate_password_hash('password123' + salt)
        student_id = c.execute("INSERT INTO users(username, password, role, email, rsa_private, salt, full_name, student_id, class_name, status) VALUES (?,?,?,?,?,?,?,?,?,?)",
                               (username, hashed_pw, 'student', f'minhvn0511+sv{i:02d}@gmail.com', generate_rsa_key_pem(), salt, f'Sinh viên {i}', f'3122410{i:03d}', f'DCQ22.1', 'approved')).lastrowid
        student_ids.append(student_id)

    # 4. Create Groups and Members
    print("Creating groups and assigning members...")
    group_ids = []
    for teacher_id in teacher_ids:
        teacher_info = c.execute("SELECT username FROM users WHERE id=?", (teacher_id,)).fetchone()
        for i in range(1, NUM_GROUPS_PER_TEACHER + 1):
            code = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
            group_id = c.execute("INSERT INTO groups(name, teacher_id, description, code) VALUES (?,?,?,?)",
                                 (f'Lớp {teacher_info[0]} - Nhóm {i}', teacher_id, 'Mô tả cho nhóm', code)).lastrowid
            group_ids.append(group_id)
            # Add some students to this group
            students_in_group = random.sample(student_ids, k=random.randint(3, 5))
            for student_id in students_in_group:
                c.execute("INSERT INTO group_members(group_id, student_id, status) VALUES (?,?,?)", (group_id, student_id, 'approved'))

    # 5. Create Exams
    print("Creating exams with different statuses...")
    now = datetime.datetime.now()
    exam_ids = []
    for teacher_id in teacher_ids:
        teacher_private_key = c.execute("SELECT rsa_private FROM users WHERE id=?", (teacher_id,)).fetchone()[0]
        teacher_groups = [g[0] for g in c.execute("SELECT id FROM groups WHERE teacher_id=?", (teacher_id,)).fetchall()]
        
        # Exam 1: Expired
        filename = f"Expired_Exam_T{teacher_id}.pdf"
        aes_key = os.urandom(32)
        enc_path, file_hash = encrypt_and_save_file(filename, aes_key)
        
        release = now - datetime.timedelta(days=2)
        expire = now - datetime.timedelta(days=1)
        signature = sign_data(bytes.fromhex(file_hash), teacher_private_key)
        encrypted_aes_key = rsa_encrypt_key(aes_key, teacher_private_key)
        exam_id = c.execute("INSERT INTO exams(filename, enc_path, release_time, expire_time, teacher_id, ten_de, encrypted_aes_key, signature, file_hash) VALUES (?,?,?,?,?,?,?,?,?)",
                  (filename, enc_path, release.strftime('%Y-%m-%dT%H:%M'), expire.strftime('%Y-%m-%dT%H:%M'), teacher_id, "Đề thi đã hết hạn", encrypted_aes_key, signature, file_hash)).lastrowid
        exam_ids.append(exam_id)

        # Exam 2: Open
        filename = f"Open_Exam_T{teacher_id}.pdf"
        aes_key = os.urandom(32)
        enc_path, file_hash = encrypt_and_save_file(filename, aes_key)

        release = now - datetime.timedelta(hours=1)
        expire = now + datetime.timedelta(hours=2)
        signature = sign_data(bytes.fromhex(file_hash), teacher_private_key)
        encrypted_aes_key = rsa_encrypt_key(aes_key, teacher_private_key)
        # Assign to a group
        assigned_group = random.choice(teacher_groups)
        students_in_group = [s[0] for s in c.execute("SELECT u.username FROM users u JOIN group_members gm ON u.id=gm.student_id WHERE gm.group_id=?", (assigned_group,)).fetchall()]
        allowed_students_str = ",".join(students_in_group)
        exam_id = c.execute("INSERT INTO exams(filename, enc_path, release_time, expire_time, teacher_id, ten_de, encrypted_aes_key, signature, file_hash, allowed_students) VALUES (?,?,?,?,?,?,?,?,?,?)",
                  (filename, enc_path, release.strftime('%Y-%m-%dT%H:%M'), expire.strftime('%Y-%m-%dT%H:%M'), teacher_id, "Đề thi đang mở", encrypted_aes_key, signature, file_hash, allowed_students_str)).lastrowid
        exam_ids.append(exam_id)

        # Exam 3: Future
        filename = f"Future_Exam_T{teacher_id}.pdf"
        aes_key = os.urandom(32)
        enc_path, file_hash = encrypt_and_save_file(filename, aes_key)

        release = now + datetime.timedelta(days=1)
        expire = now + datetime.timedelta(days=1, hours=2)
        signature = sign_data(bytes.fromhex(file_hash), teacher_private_key)
        encrypted_aes_key = rsa_encrypt_key(aes_key, teacher_private_key)
        exam_id = c.execute("INSERT INTO exams(filename, enc_path, release_time, expire_time, teacher_id, ten_de, encrypted_aes_key, signature, file_hash) VALUES (?,?,?,?,?,?,?,?,?)",
                  (filename, enc_path, release.strftime('%Y-%m-%dT%H:%M'), expire.strftime('%Y-%m-%dT%H:%M'), teacher_id, "Đề thi sắp tới", encrypted_aes_key, signature, file_hash)).lastrowid
        exam_ids.append(exam_id)

    # 6. Create Audit Logs
    print("Creating audit logs...")
    open_exams = c.execute("SELECT id, allowed_students FROM exams WHERE release_time < ? AND expire_time > ?", (now.strftime('%Y-%m-%dT%H:%M'), now.strftime('%Y-%m-%dT%H:%M'))).fetchall()
    for exam_id, allowed_students_str in open_exams:
        if allowed_students_str:
            allowed_users = allowed_students_str.split(',')
            user_to_log = c.execute("SELECT id FROM users WHERE username=?", (random.choice(allowed_users),)).fetchone()
            if user_to_log:
                c.execute("INSERT INTO audit_logs(user_id, exam_id, action, timestamp, ip_address) VALUES (?,?,?,?,?)",
                          (user_to_log[0], exam_id, 'view_exam', (now - datetime.timedelta(minutes=10)).strftime('%Y-%m-%d %H:%M:%S'), '127.0.0.1'))

    conn.commit()
    conn.close()
    print("\n--- Seeding Complete! ---")
    print("Database has been populated with sample data.")
    print("\nSample credentials (password for all is 'password123'):")
    print("- admin / admin123")
    print("- teacher1, teacher2")
    print("- student1, student2, ..., student10")

if __name__ == '__main__':
    seed_database()
