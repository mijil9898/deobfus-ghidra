# Bộ Kiểm Thử — Module 0

Thư mục này chứa **4 chương trình C** dùng làm binary kiểm thử cho module
deobfuscation chuỗi (sẽ viết ở các module sau).

## Cấu trúc file

| File | Thuật toán mã hoá | Hàm giải mã | Chuỗi gốc |
|---|---|---|---|
| `xor_simple.c` | XOR, khoá 1 byte (`0x41`) | `decode_xor` | Hello, World, Secret |
| `xor_multibyte.c` | XOR, khoá 4 byte (`DE AD BE EF`) | `decode_xor_multi` | OpenAI, Ghidra |
| `add_rol.c` | ADD (khoá `0x05`) + ROL (xoay 3 bit) | `decode_add_rol` | Alpha, Beta |
| `safe.c` | **Không có** (chỉ checksum/swap/mask) | *(không có)* | *(không có)* |

## Cách biên dịch

```bash
# Mỗi file biên dịch 3 kiểu:
#   -O0           : không tối ưu, giữ tên hàm (dễ reverse)
#   -O2           : tối ưu mạnh, nhưng GIỮ symbol để đối chiếu
#   -O2 -s        : tối ưu mạnh, xoá symbol (khó reverse hơn)

gcc -O0    -o bin/xor_simple_O0     xor_simple.c
gcc -O2    -o bin/xor_simple_O2_sym xor_simple.c
gcc -O2 -s -o bin/xor_simple_O2     xor_simple.c

gcc -O0    -o bin/xor_multibyte_O0     xor_multibyte.c
gcc -O2    -o bin/xor_multibyte_O2_sym xor_multibyte.c
gcc -O2 -s -o bin/xor_multibyte_O2     xor_multibyte.c

gcc -O0    -o bin/add_rol_O0     add_rol.c
gcc -O2    -o bin/add_rol_O2_sym add_rol.c
gcc -O2 -s -o bin/add_rol_O2     add_rol.c

gcc -O0    -o bin/safe_O0     safe.c
gcc -O2    -o bin/safe_O2_sym safe.c
gcc -O2 -s -o bin/safe_O2     safe.c
```

Hoặc chạy script tự động (khuyên dùng):
```bash
bash check_all.sh
```

## Cách kiểm tra

### Cách 1: Chạy binary trực tiếp
```bash
./bin/xor_simple_O0
# Kết quả mong đợi:
# Hello
# World
# Secret
```

### Cách 2: Dùng script Python (không cần gcc)
```bash
python verify_encoding.py
# Kiểm tra tất cả giá trị mã hoá đúng, không cần biên dịch
```

### Cách 3: Script tự động tổng hợp (biên dịch + chạy + kiểm tra ngặt nghèo)
```bash
bash check_all.sh
# Script này sẽ kiểm tra:
# - Biên dịch 3 biến thể (-O0, -O2_sym, -O2 stripped)
# - Đầu ra phải đúng
# - KHÔNG lộ chuỗi gốc dạng rõ (dùng strings)
# - Hàm giải mã không bị xóa mất do tối ưu (dùng nm)
# - Tạo file expected_addresses.json tự động
```

## File tham chiếu

- `expected.json` — Kết quả đúng (ground truth) cố định: tên hàm giải mã, thuật toán,
  khoá, byte mã hoá, chuỗi gốc cho từng chương trình.
- `expected_addresses.json` — File tự động sinh bởi `check_all.sh`, chứa địa chỉ entry thực tế của các hàm giải mã trong binary (dùng để đối chiếu cho bản stripped).
- `verify_encoding.py` — Script Python xác minh giá trị mã hoá.
- `check_all.sh` — Script bash tổng hợp mọi kiểm tra (biên dịch, strings, nm, output).

## Mục đích

Binary từ bộ kiểm thử này sẽ được nạp vào Ghidra ở các module sau.
Module deobfuscation cần:
1. **Tìm đúng** hàm giải mã trong 3 file đầu
2. **Không gắn cờ nhầm** bất kỳ hàm nào trong `safe.c`
3. **Tính lại** chuỗi gốc và khớp với `expected.json`
