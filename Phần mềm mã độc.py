import hashlib
import os

# Danh sách các chuỗi nghi vấn thường thấy trong mã độc
SUSPICIOUS_STRINGS = [
    "eval(", "exec(", "os.system(", "subprocess", "base64", "socket",
    "pickle", "__import__", "open(", "write(", "compile(", "marshal"
]

def hash_file(file_path):
    """Tính toán SHA-256 của tệp."""
    sha256 = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            while chunk := f.read(4096):
                sha256.update(chunk)
        return sha256.hexdigest()
    except Exception as e:
        print(f"Lỗi khi đọc file: {e}")
        return None

def scan_file(file_path):
    """Quét file để tìm các chuỗi nghi vấn."""
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
            findings = [s for s in SUSPICIOUS_STRINGS if s in content]
            return findings
    except Exception as e:
        print(f"Lỗi khi quét nội dung file: {e}")
        return []

def main():
    file_path = input("Nhập đường dẫn tới tệp cần kiểm tra: ").strip()

    if not os.path.isfile(file_path):
        print(" Tệp không tồn tại.")
        return

    print("\n Đang kiểm tra mã độc...")

    # Tính hash
    file_hash = hash_file(file_path)
    if file_hash:
        print(f" SHA-256: {file_hash}")
    else:
        print(" Không thể tính toán SHA-256.")

    # Quét mã độc cơ bản
    suspicious = scan_file(file_path)
    if suspicious:
        print("\n Phát hiện chuỗi nghi vấn:")
        for s in suspicious:
            print(f"  - {s}")
    else:
        print("\n Không phát hiện chuỗi nghi vấn nào.")

if __name__ == "__main__":
    main()
