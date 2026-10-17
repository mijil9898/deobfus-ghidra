# Ghidra Auto-Deobfuscation

Công cụ Python dùng [PyGhidra](https://github.com/NationalSecurityAgency/ghidra/tree/master/Ghidra/Features/PyGhidra) để **tự động tìm hàm giải mã chuỗi** và giải mã chúng trong binary ELF.

---

## Tính năng

| Thuật toán       | Mô tả                                         |
|------------------|-----------------------------------------------|
| `xor`            | XOR từng byte với khoá 1 byte cố định         |
| `xor_multi`      | XOR với khoá nhiều byte, lặp vòng             |
| `add`            | Trừ khoá 1 byte (inverse của ADD)             |
| `add_rol`        | ROR rồi SUB khoá (inverse của ADD + ROL)      |

Heuristic phát hiện hàm giải mã dựa trên **Pcode** (IR nội bộ của Ghidra):
- Có vòng lặp trong C decompiled
- Có phép `XOR` / `ADD` / `ROL` trên byte đơn
- Có cả `LOAD` và `STORE` kích thước 1 byte
- Ít hơn 200 Pcode ops (tránh hàm to)

---

## Cài đặt nhanh

```bash
# 1. Cài Ghidra ≥ 12.x, đặt GHIDRA_INSTALL_DIR
source env.sh            # hoặc export tay
pip install -r requirements.txt
```

Yêu cầu: **Python ≥ 3.11**, **JDK 21**, Ghidra 12.1.4+.

---

## Chạy

```bash
# Phân tích binary, xuất JSON ra stdout
python3 ghidra_auto.py <binary>

# Lưu kết quả vào file
python3 ghidra_auto.py <binary> --json-out ket_qua.json

# Chỉ tìm ứng viên hàm giải mã (không giải mã chuỗi)
python3 find_candidates.py <binary>

# Debug Pcode tại địa chỉ cụ thể
python3 debug_pcode.py <binary> <địa_chỉ>
```

### Kết quả JSON mẫu

```json
{
  "binary": "test_bins/bin/xor_simple_O0",
  "results": [
    {
      "call_addr": "0x10120c",
      "dest": "local_38",
      "length": 5,
      "key": "0x41",
      "raw_hex": "09242d2d2e",
      "decoded": "Hello",
      "status": "ok"
    }
  ]
}
```

---

## Kiểm thử

```bash
# Biên dịch binary và kiểm tra toàn bộ (0 lỗi)
bash test_bins/check_all.sh

# Kiểm tra encoding file Python (UTF-8 BOM, Latin-1)
python3 test_bins/verify_encoding.py
```

### Ground truth

File [`test_bins/expected.json`](test_bins/expected.json) chứa chuỗi plaintext mong đợi cho từng binary kiểm thử.

| Binary           | Chuỗi mong đợi                    |
|------------------|-----------------------------------|
| `xor_simple`     | `Hello`, `World`, `Secret`        |
| `xor_multibyte`  | `OpenAI`, `Ghidra`                |
| `add_rol`        | `Alpha`, `Beta`                   |
| `safe`           | _(rỗng — không có hàm giải mã)_   |

---

## Docker

```bash
# Build
docker build -t ghidra-deobf .

# Chạy (mount binary read-only)
docker run --rm -v /path/to/bins:/bins:ro ghidra-deobf /bins/my_binary
```

---

## Cấu trúc dự án

```
.
├── ghidra_auto.py        # Script chính: tìm + giải mã chuỗi
├── find_candidates.py    # Chỉ tìm ứng viên hàm giải mã
├── pcode_analysis.py     # Module dùng chung: heuristic Pcode
├── debug_pcode.py        # Debug Pcode tại địa chỉ cụ thể
├── requirements.txt      # Phụ thuộc Python (phiên bản ghim)
├── env.sh                # Thiết lập biến môi trường
├── Dockerfile
└── test_bins/
    ├── xor_simple.c      # Binary mẫu: XOR 1 byte
    ├── xor_multibyte.c   # Binary mẫu: XOR nhiều byte
    ├── add_rol.c         # Binary mẫu: ADD + ROL
    ├── safe.c            # Binary mẫu: KHÔNG có giải mã
    ├── expected.json     # Ground truth chuỗi plaintext
    ├── check_all.sh      # Script kiểm tra tổng hợp
    └── verify_encoding.py # Kiểm tra encoding file .py
```

---

## CI/CD

Workflow GitHub Actions ([`.github/workflows/build.yml`](.github/workflows/build.yml)):

1. **SAST** — Semgrep quét mã nguồn Python
2. **Build & Test** — Docker build, smoke test `--help`, `check_all.sh`, functional test 4 binary
3. **Trivy** — Quét CVE HIGH/CRITICAL (security gate)
4. **Publish** — Push lên GHCR chỉ khi push vào `main`
5. **Scheduled scan** — Quét hằng ngày không dùng cache, không làm đỏ CI

---


