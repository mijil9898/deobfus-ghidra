# Bảng Kiểm Soát Tiến Độ (Project Checklist)

Dưới đây là các mốc công việc đã và đang được thực hiện, giúp chúng ta theo dõi sát sao tiến độ từ Module 0 đến khi hoàn tất.

## 0. Môi trường và Tổ chức (Khởi tạo)
- [x] Tạo `.gitignore` chứa `bin/`, `expected_addresses.json`, v.v. để git không track file rác.
- [ ] Di chuyển thư mục dự án vào file system thuần của Linux (VD: `~/ghidra-deobf`) thay vì để ở `/mnt/d/` nhằm tránh lỗi của `pyghidra` với đường dẫn và NTFS mount. (Cần User tự thao tác)
- [ ] Khởi tạo Git repo và commit ban đầu (`git init`, `git add .`, `git commit -m "Init"`).

## 1. Module 0: Bộ kiểm thử (`test_bins`)
- [x] Sửa mã nguồn C (`__attribute__((noinline))`) để ngăn `-O2` xoá mất hàm giải mã.
- [x] Viết script xác minh logic giải mã Python (`verify_encoding.py`) -> PASS.
- [x] Viết script Bash (`check_all.sh`) biên dịch 3 biến thể `-O0`, `-O2_sym`, `-O2` stripped cho 4 mẫu malware mô phỏng.
- [x] Sửa lỗi Bash ngắt giữa chừng do `set -e` và `((PASS++))`.
- [x] Gom toàn bộ file binary xuất ra vào một thư mục dọn dẹp `bin/`.
- [x] Tự động trích xuất `expected_addresses.json` (ground truth) dùng lệnh `nm`.
- [x] Chạy thật 100% (38/38 bài test báo Đạt).

## 2. Module 1: Tìm hàm giải mã ứng viên (Heuristic)
- [x] Viết file Python `find_candidates.py` sử dụng `pyghidra`.
- [x] Cài đặt thuật toán heuristc quét Pcode:
  - Hàm có vòng lặp (while/for/do).
  - Có các chỉ thị `INT_XOR`, `INT_ADD`, `INT_LEFT` trên byte (1 byte `LOAD`/`STORE`).
  - Lọc các hàm quá dài (>200 opcodes) và bỏ qua Thunk/External.
- [x] **Đã kiểm tra thành công:** Chạy thử với các binary trong `test_bins/bin/` bắt trúng chính xác hàm giải mã `decode_xor`.

## 3. Module 2: Trích xuất tham số và tính toán (Đã hoàn thành)
- [x] Viết script phân tích Call Graph (tìm nơi gọi hàm giải mã).
- [x] Bắt các tham số được đẩy vào hàm giải mã (xử lý `strncpy`, gán mảng rải rác, pointer offset).
- [x] Dùng Python giả lập lại vòng lặp giải mã để tính ra chuỗi gốc (XOR, ADD, ADD+ROL).
- [x] Ghi comment và bookmark trực tiếp vào file của Ghidra thông qua transaction.

---
**Ghi chú của Mentor:**
File này sẽ liên tục được cập nhật. Các mục có dấu `[x]` là những phần chúng ta đã hoàn thành vững chắc. Các mục `[ ]` là việc cần làm tiếp.
