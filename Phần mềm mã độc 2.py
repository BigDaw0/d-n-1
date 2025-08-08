import hashlib

# Danh sách các chuỗi nghi vấn thường xuất hiện trong mã độc
suspect_keywords = ["eval(", "exec(", "base64", "import os", "__import__", "subprocess", "marshal"]

def hash_file_sha256(filename):
    with open(filename, "rb") as f:
        data = f.read()
        return hashlib.sha256(data).hexdigest()

def check_file_for_malware(filepath):
    print("Đang kiểm tra mã độc...")
    sha256 = hash_file_sha256(filepath)
    print(f"SHA-256: {sha256}\n")

    # Đọc nội dung file
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read()

    # Kiểm tra xem có chuỗi nghi vấn nào không
    found = []
    for keyword in suspect_keywords:
        if keyword in content:
            found.append(keyword)

    # Xuất kết quả đơn giản
    if found:
        print(" Tệp này có mã độc!")
        print("Chuỗi nghi vấn tìm thấy:")
        for k in found:
            print(" -", k)
    else:
        print(" Tệp này không có mã độc.")

# ---- Chạy chương trình chính ----
path = input("Nhập đường dẫn tới tệp cần kiểm tra: ")
check_file_for_malware(path)
