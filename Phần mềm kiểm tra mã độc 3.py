import os
import hashlib
from datetime import datetime
from docx import Document
import openpyxl
import PyPDF2

# Danh sách từ khóa nghi vấn
suspicious_keywords = ["exec(", "eval(", "base64", "subprocess", "import os", "os.system", "compile(", "globals("]

# File log để ghi kết quả
log_file = "scan_log.txt"

# Hàm tạo mã băm SHA-256
def hash_file(file_path):
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(4096):
            sha256.update(chunk)
    return sha256.hexdigest()

# Hàm trích xuất nội dung theo loại file
def extract_text(file_path):
    ext = os.path.splitext(file_path)[1].lower()
    try:
        if ext in [".txt", ".py", ".csv", ".log"]:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                return f.read()

        elif ext == ".docx":
            doc = Document(file_path)
            return "\n".join(p.text for p in doc.paragraphs)

        elif ext == ".xlsx":
            wb = openpyxl.load_workbook(file_path, data_only=True)
            text = ""
            for sheet in wb.worksheets:
                for row in sheet.iter_rows(values_only=True):
                    line = " ".join(str(cell) for cell in row if cell)
                    text += line + "\n"
            return text

        elif ext == ".pdf":
            with open(file_path, "rb") as f:
                reader = PyPDF2.PdfReader(f)
                return "\n".join(page.extract_text() or "" for page in reader.pages)

        else:
            return ""  # Không hỗ trợ định dạng này
    except Exception as e:
        print(f" Lỗi đọc {file_path}: {e}")
        return ""

# Hàm kiểm tra mã độc và ghi
def check_file(file_path):
    content = extract_text(file_path)
    if not content:
        return

    found = [kw for kw in suspicious_keywords if kw in content]
    file_hash = hash_file(file_path)
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with open(log_file, "a", encoding="utf-8") as log:
        log.write(f"\n--- {now} ---\n")
        log.write(f"File: {file_path}\n")
        log.write(f"SHA-256: {file_hash}\n")
        if found:
            log.write(" Tệp này CÓ mã độc\n")
            log.write("Từ khóa nghi vấn: " + ", ".join(found) + "\n")
        else:
            log.write(" Tệp này KHÔNG có mã độc\n")

    # In ra màn hình
    if found:
        print(f" {file_path} → CÓ mã độc: {', '.join(found)}")
    else:
        print(f" {file_path} → Không có mã độc")

# Hàm quét toàn bộ thư mục
def scan_folder(folder_path):
    print(f"\n Bắt đầu quét thư mục: {folder_path}\n")
    for root, _, files in os.walk(folder_path):
        for name in files:
            path = os.path.join(root, name)
            check_file(path)
    print(f"\n Đã hoàn tất. Xem log trong '{log_file}'")
    # Gợi ý mở file log sau khi quét xong (chỉ dành cho Windows)
    try:
        os.system(f'notepad "{log_file}"')  # Hoặc notepad++ nếu bạn có
    except:
        pass

# --- CHẠY ---
folder = input("Nhập đường dẫn tới thư mục cần kiểm tra: ")
scan_folder(folder)
