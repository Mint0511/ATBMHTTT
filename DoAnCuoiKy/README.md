# HỆ THỐNG QUẢN LÝ & PHÂN PHỐI ĐỀ THI BẢO MẬT (SECURE EXAM SYSTEM)

Đồ án môn học: An Toàn Bảo Mật Hệ Thống Thông Tin
Sinh viên thực hiện: [Tên của bạn]
MSSV: [Mã số sinh viên]

---

## 📖 KỊCH BẢN DEMO & BẢO VỆ ĐỒ ÁN (DEMO SCRIPT)

Dưới đây là trình tự demo được thiết kế để chứng minh tính **Bảo mật (Security)**, **Toàn vẹn (Integrity)** và **Thực tế (Practicality)** của hệ thống.

### GIAI ĐOẠN 1: GIÁO VIÊN UPLOAD & MÃ HOÁ (CONFIDENTIALITY)

**Mục tiêu:** Chứng minh đề thi được mã hóa ngay lập tức và khóa được bảo vệ chặt chẽ.

1.  **Thao tác:** Đăng nhập tài khoản Giáo viên -> Vào menu **Upload Đề Thi**.
2.  **Hành động:** Upload một file PDF đề thi, đặt thời gian mở/đóng, chọn chế độ xác thực (ví dụ: *Kết hợp OTP & PIN*).
3.  **Giải thích quy trình ngầm (Backend):**
    *   Hệ thống sinh ngẫu nhiên một khóa **AES-256** (Session Key).
    *   Dùng khóa AES này mã hóa file PDF (AES-GCM Mode).
    *   Dùng **RSA Public Key** của giáo viên để mã hóa chính cái khóa AES đó (Key Wrapping).
    *   File gốc bị xóa, chỉ lưu file đã mã hóa (`enc_...`) trên ổ cứng.
4.  **Minh chứng:**
    *   Mở thư mục `uploads/` trên máy tính.
    *   Thử mở file `enc_...` bằng phần mềm đọc PDF bình thường -> **Lỗi (Không đọc được)**.
    *   *Kết luận:* Hacker lấy được file này cũng vô dụng vì không có Private Key.

### GIAI ĐOẠN 2: KIỂM TRA TOÀN VẸN DỮ LIỆU (INTEGRITY)

**Mục tiêu:** Chứng minh hệ thống phát hiện được mọi sự thay đổi trái phép (Tampering).

1.  **Thao tác:** Tại Dashboard Giáo viên, tìm đề thi vừa upload.
2.  **Hành động:** Nhấn nút **"Phá" (Tamper)** (Nút màu vàng).
    *   *Giải thích:* Chức năng này giả lập việc Hacker hoặc virus thay đổi 1 bit nhỏ trong file mã hóa trên server.
3.  **Hậu quả:**
    *   Thử bấm **"Xem"** hoặc **"Soi"**.
    *   Hệ thống báo lỗi: *"Integrity Check Failed"* hoặc *"Decryption Error"*.
    *   *Lý do:* Thuật toán AES-GCM có cơ chế **Auth Tag**. Nếu dữ liệu bị sửa, Tag sẽ không khớp.
4.  **Khắc phục:** Nhấn nút **"Sửa" (Restore)** để khôi phục file về trạng thái gốc.

### GIAI ĐOẠN 3: SINH VIÊN THI & KIỂM SOÁT (DRM & ACCESS CONTROL)

**Mục tiêu:** Chứng minh tính linh hoạt (Online/Offline) và chống sao chép.

1.  **Thao tác:** Đăng nhập tài khoản Sinh viên.
2.  **Kịch bản A: Thi Online (Dùng OTP)**
    *   Bấm "Gửi OTP" -> Check Email -> Nhập OTP.
    *   *Ý nghĩa:* **Non-repudiation (Chống chối bỏ)**. Chỉ chủ sở hữu email mới nhận được mã.
3.  **Kịch bản B: Thi Offline/Tại lớp (Dùng PIN)**
    *   Giáo viên đọc Mã PIN (hiển thị trên Dashboard GV).
    *   Sinh viên nhập PIN -> Vào thi ngay lập tức (Không phụ thuộc Email/Internet quốc tế).
4.  **Trải nghiệm làm bài (DRM):**
    *   Đề thi hiện ra trên trình duyệt.
    *   **Thử thách:** Thử bôi đen văn bản, thử chuột phải (Right-click), thử tìm nút Download. -> **Tất cả đều bị vô hiệu hóa**.
    *   **Watermark:** Chỉ vào các dòng chữ mờ chéo màn hình (MSSV + Tên).
    *   *Kết luận:* Nếu sinh viên chụp ảnh màn hình gửi ra ngoài, danh tính sẽ bị lộ ngay lập tức.

### GIAI ĐOẠN 4: MINH BẠCH HOÁ KỸ THUẬT (CRYPTO INSPECTOR)

**Mục tiêu:** Trả lời câu hỏi *"Em có thực sự mã hóa không hay chỉ đổi đuôi file?"*.

1.  **Thao tác:** Quay lại Dashboard Giáo viên -> Nhấn nút **"Soi" (Debug)** (Nút màu đen).
2.  **Trình bày:** Trang này "mổ xẻ" cấu trúc file mã hóa:
    *   **IV (Initialization Vector):** Công khai, ngẫu nhiên mỗi lần.
    *   **Auth Tag:** Dùng để kiểm tra toàn vẹn.
    *   **Encrypted AES Key:** Khóa AES đang bị khóa bởi RSA.
    *   **Recovered AES Key:** Khóa AES sau khi dùng Private Key của giáo viên để mở.
3.  **Ý nghĩa:** Đây là bằng chứng toán học cho thấy hệ thống vận hành đúng chuẩn Cryptography quốc tế.

### GIAI ĐOẠN 5: HẬU KIỂM & ĐỐI CHỨNG (AUDIT LOGS)

**Mục tiêu:** Giải quyết tranh chấp *"Em không nhận được đề"*.

1.  **Thao tác:** Dashboard Giáo viên -> Nhấn nút **"Logs"** (Nút màu xanh dương).
2.  **Trình bày:**
    *   Show danh sách: *Nguyễn Văn A - 3122410xxx - Đã xem đề lúc 09:00:05 - IP: 192.168.1.5*.
    *   Trạng thái: **Thành công**.
3.  **Kết luận:** Đây là bằng chứng kỹ thuật số không thể chối cãi.

---

## ⚙️ CÀI ĐẶT & CHẠY DỰ ÁN

### Yêu cầu hệ thống
*   Python 3.8+
*   Các thư viện: Flask, Cryptography, PyOTP...

### Cài đặt
1.  Mở terminal tại thư mục dự án.
2.  Cài đặt thư viện:
    ```bash
    pip install flask flask-login cryptography pyotp qrcode
    ```
3.  Chạy ứng dụng:
    ```bash
    python app.py
    ```
4.  Truy cập: `http://localhost:5000`

### Tài khoản Demo
*   **Admin:** `admin` / `admin123`
*   **Giáo viên:** Đăng ký mới hoặc dùng user có sẵn (role teacher).
*   **Sinh viên:** Đăng ký mới (role student).

---

## 🛡️ CÔNG NGHỆ SỬ DỤNG
*   **Backend:** Flask (Python).
*   **Database:** SQLite.
*   **Encryption:**
    *   **AES-256-GCM:** Mã hóa nội dung đề thi (Confidentiality & Integrity).
    *   **RSA-2048:** Mã hóa khóa AES (Key Exchange/Protection).
    *   **SHA-256:** Hashing mật khẩu và kiểm tra toàn vẹn file.
*   **Frontend:** Bootstrap 5, PDF.js (Customized for DRM).

