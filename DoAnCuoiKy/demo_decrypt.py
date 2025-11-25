import base64
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

class DecryptApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Tool Demo Giải Mã AES-GCM Thủ Công")
        self.root.geometry("900x700")
        
        # Style
        style = ttk.Style()
        style.configure("TLabel", font=("Segoe UI", 10))
        style.configure("TButton", font=("Segoe UI", 11, "bold"))
        style.configure("Header.TLabel", font=("Segoe UI", 14, "bold"), foreground="#2c3e50")
        
        # Header
        ttk.Label(root, text="DEMO GIẢI MÃ & KIỂM TRA TOÀN VẸN (AES-GCM)", style="Header.TLabel").pack(pady=10)
        
        # 1. Key Input
        frame_key = ttk.LabelFrame(root, text="1. Nhập Khóa AES (Hex) - Lấy từ trang 'Soi'", padding=10)
        frame_key.pack(fill="x", padx=15, pady=5)
        
        self.entry_key = ttk.Entry(frame_key, font=("Consolas", 11))
        self.entry_key.pack(fill="x", expand=True)
        # Placeholder effect logic could be added, but simple text is fine
        
        # 2. Base64 Input
        frame_data = ttk.LabelFrame(root, text="2. Nhập Dữ liệu Base64 - Lấy từ trang 'Xem Enc'", padding=10)
        frame_data.pack(fill="both", expand=True, padx=15, pady=5)
        
        self.text_data = scrolledtext.ScrolledText(frame_data, height=8, font=("Consolas", 10))
        self.text_data.pack(fill="both", expand=True)
        
        # 3. Action Button
        btn_frame = ttk.Frame(root, padding=10)
        btn_frame.pack(fill="x")
        
        self.btn_decrypt = ttk.Button(btn_frame, text="🔓 TIẾN HÀNH GIẢI MÃ & TÁCH FILE", command=self.run_decryption)
        self.btn_decrypt.pack(fill="x", ipady=8, padx=5)
        
        # 4. Log Output
        frame_log = ttk.LabelFrame(root, text="3. Nhật ký xử lý (Log chi tiết)", padding=10)
        frame_log.pack(fill="both", expand=True, padx=15, pady=10)
        
        self.text_log = scrolledtext.ScrolledText(frame_log, height=12, font=("Consolas", 10), state='disabled', bg="#f8f9fa")
        self.text_log.pack(fill="both", expand=True)

    def log(self, message, tag=None):
        self.text_log.config(state='normal')
        self.text_log.insert(tk.END, message + "\n", tag)
        self.text_log.see(tk.END)
        self.text_log.config(state='disabled')

    def run_decryption(self):
        # Clear log
        self.text_log.config(state='normal')
        self.text_log.delete("1.0", tk.END)
        self.text_log.config(state='disabled')
        
        hex_key = self.entry_key.get().strip()
        b64_data = self.text_data.get("1.0", tk.END).strip()
        
        if not hex_key:
            messagebox.showerror("Thiếu thông tin", "Vui lòng nhập Khóa AES (Hex)!")
            return
        if not b64_data:
            messagebox.showerror("Thiếu thông tin", "Vui lòng nhập dữ liệu Base64!")
            return
            
        try:
            self.log("--- BẮT ĐẦU QUÁ TRÌNH GIẢI MÃ ---")
            
            # 1. Parse Key
            clean_key_hex = hex_key.replace(" ", "")
            try:
                key = bytes.fromhex(clean_key_hex)
            except:
                raise ValueError("Khóa AES không đúng định dạng Hex")
                
            self.log(f"✅ [1] KEY AES: Đã nhận diện {len(key)} bytes ({len(key)*8} bits)")
            if len(key) != 32:
                self.log(f"⚠️ Cảnh báo: Key AES thường là 32 bytes (256 bit). Key này là {len(key)} bytes.")
            
            # 2. Decode Base64
            try:
                full_data = base64.b64decode(b64_data)
            except:
                raise ValueError("Dữ liệu không phải Base64 hợp lệ")
                
            self.log(f"✅ [2] BASE64 DECODE: Tổng kích thước file mã hóa là {len(full_data)} bytes")
            
            # 3. Split Components
            if len(full_data) < 28:
                raise ValueError("Dữ liệu quá ngắn, không đủ chứa IV và Tag")
                
            iv = full_data[:12]
            tag = full_data[12:28]
            ciphertext = full_data[28:]
            
            self.log(f"✅ [3] TÁCH THÀNH PHẦN (Theo cấu trúc quy định):")
            self.log(f"    🔹 IV (Nonce) [12 bytes]: {iv.hex().upper()}")
            self.log(f"    🔹 Tag (MAC)  [16 bytes]: {tag.hex().upper()}")
            self.log(f"    🔹 Ciphertext [Còn lại]:  {len(ciphertext)} bytes")
            
            # 4. Decrypt
            self.log(f"⏳ [4] ĐANG GIẢI MÃ AES-256-GCM...")
            decryptor = Cipher(
                algorithms.AES(key),
                modes.GCM(iv, tag)
            ).decryptor()
            
            # Nếu Tag không khớp, dòng này sẽ throw InvalidTag
            decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
            
            self.log(f"✅ [THÀNH CÔNG] Dữ liệu toàn vẹn! Tag xác thực khớp hoàn toàn.")
            
            # 5. Save File
            output_filename = "KET_QUA_GIAI_MA.pdf"
            with open(output_filename, "wb") as f:
                f.write(decrypted_data)
                
            self.log(f"💾 [5] KẾT QUẢ: Đã lưu file '{output_filename}'")
            
            # Preview header
            if decrypted_data.startswith(b'%PDF'):
                self.log(f"    📄 Phát hiện Header PDF hợp lệ (%PDF...)")
            
            messagebox.showinfo("Thành công", f"Đã giải mã xong!\nFile đã được lưu thành: {output_filename}")
            
            # Open folder
            os.startfile(os.getcwd())
            
        except Exception as e:
            self.log(f"❌ [THẤT BẠI] Lỗi: {str(e)}")
            if "Tag" in str(e) or "AuthenticationTag" in str(e):
                messagebox.showerror("Cảnh báo bảo mật", "PHÁT HIỆN FILE BỊ CAN THIỆP!\n(Tag xác thực không khớp - Integrity Check Failed)")
            else:
                messagebox.showerror("Lỗi", f"Giải mã thất bại:\n{str(e)}")

if __name__ == "__main__":
    root = tk.Tk()
    app = DecryptApp(root)
    root.mainloop()
