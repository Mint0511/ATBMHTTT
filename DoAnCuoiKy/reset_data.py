import sqlite3
import os
import secrets
import datetime
import base64
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Configuration
DB_PATH = 'exam.db'
UPLOAD_FOLDER = 'uploads'

# Ensure upload folder exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def get_db():
    return sqlite3.connect(DB_PATH)

def hash_file(data):
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)
    return digest.finalize().hex()

def sign_data(data, private_key_pem):
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

def rsa_encrypt_key(aes_key, private_key_pem):
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

def create_dummy_pdf(title, body_text):
    # Simple PDF generator (Text only, Latin-1)
    # Escape special chars
    def escape(s):
        return s.replace('\\', '\\\\').replace('(', '\\(').replace(')', '\\)')

    # Split body into lines
    lines = body_text.split('\n')
    
    # Construct Text Stream
    # Title at top
    stream_content = "BT\n/F1 24 Tf\n50 750 Td\n(" + escape(title) + ") Tj\nET\n"
    
    # Body text
    stream_content += "BT\n/F1 12 Tf\n50 700 Td\n15 TL\n" # 15 Leading
    for line in lines:
        stream_content += "(" + escape(line) + ") Tj T*\n"
    stream_content += "ET"
    
    stream_len = len(stream_content)
    
    pdf = (
        f"%PDF-1.5\n"
        f"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
        f"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"
        f"3 0 obj\n<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 4 0 R >> >> /MediaBox [0 0 612 792] /Contents 5 0 R >>\nendobj\n"
        f"4 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n"
        f"5 0 obj\n<< /Length {stream_len} >>\nstream\n{stream_content}\nendstream\nendobj\n"
        f"xref\n"
        f"0 6\n"
        f"0000000000 65535 f \n"
        f"0000000010 00000 n \n"
        f"0000000060 00000 n \n"
        f"0000000117 00000 n \n"
        f"0000000240 00000 n \n"
        f"0000000327 00000 n \n"
        f"trailer\n<< /Size 6 /Root 1 0 R >>\n"
        f"startxref\n450\n%%EOF"
    )
    return pdf.encode('latin-1')

def reset_and_seed():
    conn = get_db()
    c = conn.cursor()

    print("--- Cleaning old data ---")
    # 1. Clear exams table
    c.execute("DELETE FROM exams")
    c.execute("DELETE FROM audit_logs")
    print("Deleted all records from 'exams' and 'audit_logs'.")

    # 2. Clear upload folder
    for f in os.listdir(UPLOAD_FOLDER):
        if f.startswith("enc_"):
            os.remove(os.path.join(UPLOAD_FOLDER, f))
    print("Deleted all encrypted files in 'uploads/'.")

    # 3. Find a teacher
    teacher = c.execute("SELECT id, username, rsa_private FROM users WHERE role='teacher'").fetchone()
    if not teacher:
        print("ERROR: No teacher found in database. Please register a teacher first.")
        return

    teacher_id, teacher_name, private_key_pem = teacher
    print(f"Using teacher: {teacher_name} (ID: {teacher_id})")

    # 4. Create Dummy Exams
    exams_data = [
        {
            "title": "De Thi Giua Ky (Demo)",
            "filename": "De_Thi_Giua_Ky.pdf",
            "offset_minutes": -60, 
            "duration_minutes": 120,
            "auth_mode": "both",
            "content": "TRUONG DAI HOC SAI GON\nKHOA CONG NGHE THONG TIN\n\nDE THI GIUA KY MON: AN TOAN BAO MAT HTTT\nThoi gian: 60 phut\n\nCau 1 (2d): Trinh bay khai niem Ma hoa doi xung va Bat doi xung.\n\nCau 2 (3d): Giai thich co che hoat dong cua AES-GCM.\n\nCau 3 (5d): Tai sao can phai bao ve Private Key nghiem ngat?"
        },
        {
            "title": "De Thi Cuoi Ky (Sap mo)",
            "filename": "De_Thi_Cuoi_Ky.pdf",
            "offset_minutes": 60, 
            "duration_minutes": 90,
            "auth_mode": "pin",
            "content": "TRUONG DAI HOC SAI GON\n\nDE THI CUOI KY (BI MAT)\n\nNoi dung de thi chua duoc tiet lo.\nVui long quay lai sau khi den gio lam bai."
        },
        {
            "title": "Kiem Tra 15 Phut (Da dong)",
            "filename": "Kiem_Tra_15p.pdf",
            "offset_minutes": -200, 
            "duration_minutes": 30, 
            "auth_mode": "otp",
            "content": "BAI KIEM TRA 15 PHUT\n\nCau 1: RSA la viet tat cua nhung ten nguoi nao?\nA. Rivest, Shamir, Adleman\nB. Robert, Samuel, Adam\n\nCau 2: Do dai khoa AES mac dinh la bao nhieu?\nA. 128 bit\nB. 256 bit"
        }
    ]

    for exam in exams_data:
        print(f"Creating exam: {exam['title']}...")
        
        # Generate PDF content
        raw_data = create_dummy_pdf(exam['title'], exam['content'])
        
        # Hash
        file_hash = hash_file(raw_data)
        
        # AES Encryption
        aes_key = os.urandom(32)
        iv = os.urandom(12)
        encryptor = Cipher(algorithms.AES(aes_key), modes.GCM(iv)).encryptor()
        ct = encryptor.update(raw_data) + encryptor.finalize()
        tag = encryptor.tag
        
        # Save File (Base64 Encoded)
        enc_filename = f"enc_{exam['filename']}"
        enc_path = os.path.join(UPLOAD_FOLDER, enc_filename)
        
        # IMPORTANT: Write as Base64 as per new requirement
        with open(enc_path, 'wb') as f:
            f.write(base64.b64encode(iv + tag + ct))
            
        # Sign Hash
        signature = sign_data(bytes.fromhex(file_hash), private_key_pem)
        
        # Encrypt AES Key
        encrypted_aes_key = rsa_encrypt_key(aes_key, private_key_pem)
        
        # Times
        now = datetime.datetime.now()
        release_time = now + datetime.timedelta(minutes=exam['offset_minutes'])
        expire_time = release_time + datetime.timedelta(minutes=exam['duration_minutes'])
        
        # PIN
        pin_code = ''.join(secrets.choice('0123456789') for _ in range(6))
        
        # Insert DB
        c.execute("""
            INSERT INTO exams(
                filename, enc_path, release_time, expire_time, teacher_id, 
                ten_de, aes_key, allowed_students, signature, file_hash, 
                encrypted_aes_key, pin_code, auth_mode, allowed_groups
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, (
            exam['filename'], enc_path, 
            release_time.strftime('%Y-%m-%dT%H:%M'), 
            expire_time.strftime('%Y-%m-%dT%H:%M'), 
            teacher_id, exam['title'], None, '', 
            signature, file_hash, encrypted_aes_key, 
            pin_code, exam['auth_mode'], ''
        ))
        
    conn.commit()
    conn.close()
    print("--- Reset and Seed Completed Successfully ---")

if __name__ == "__main__":
    reset_and_seed()
