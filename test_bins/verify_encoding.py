"""
verify_encoding.py — Xác minh tất cả giá trị mã hoá trong bộ kiểm thử
Chạy: python verify_encoding.py
Không cần gcc, không cần Ghidra. Chỉ cần Python 3.
"""


def xor_encode(plaintext: bytes, key: int) -> list[int]:
    """Mã hoá XOR 1 byte: mỗi byte XOR với key."""
    return [b ^ key for b in plaintext]


def xor_multi_encode(plaintext: bytes, key: bytes) -> list[int]:
    """Mã hoá XOR nhiều byte: byte[i] XOR key[i % len(key)]."""
    return [b ^ key[i % len(key)] for i, b in enumerate(plaintext)]


def add_rol_encode(plaintext: bytes, key_add: int, shift_rol: int) -> list[int]:
    """Mã hoá kết hợp ADD rồi ROL: mỗi byte cộng key_add, rồi xoay trái shift_rol bit."""
    result = []
    for b in plaintext:
        tmp = (b + key_add) & 0xFF             # bước 1: ADD
        enc = ((tmp << shift_rol) | (tmp >> (8 - shift_rol))) & 0xFF  # bước 2: ROL
        result.append(enc)
    return result


def verify(name: str, expected: list[int], actual: list[int], plain: str) -> bool:
    """So sánh mảng byte mã hoá, in PASS hoặc FAIL."""
    ok = expected == actual
    tag = "PASS" if ok else "FAIL"
    print(f"  [{tag}] {name} -> \"{plain}\"")
    if not ok:
        print(f"    Mong đợi : {[hex(x) for x in expected]}")
        print(f"    Thực tế  : {[hex(x) for x in actual]}")
    return ok


def main():
    tổng_pass = 0
    tổng_fail = 0

    # ===== xor_simple: XOR khoá 0x41 =====
    print("=== xor_simple (XOR key=0x41) ===")
    tests_xor = [
        ([0x09, 0x24, 0x2D, 0x2D, 0x2E], "Hello"),
        ([0x16, 0x2E, 0x33, 0x2D, 0x25], "World"),
        ([0x12, 0x24, 0x22, 0x33, 0x24, 0x35], "Secret"),
    ]
    for expected_enc, plain in tests_xor:
        actual = xor_encode(plain.encode(), 0x41)
        if verify(f"XOR('{plain}', 0x41)", expected_enc, actual, plain):
            tổng_pass += 1
        else:
            tổng_fail += 1

    # ===== xor_multibyte: XOR khoá {DE, AD, BE, EF} =====
    print("\n=== xor_multibyte (XOR key=DE AD BE EF) ===")
    key_multi = bytes([0xDE, 0xAD, 0xBE, 0xEF])
    tests_multi = [
        ([0x91, 0xDD, 0xDB, 0x81, 0x9F, 0xE4], "OpenAI"),
        ([0x99, 0xC5, 0xD7, 0x8B, 0xAC, 0xCC], "Ghidra"),
    ]
    for expected_enc, plain in tests_multi:
        actual = xor_multi_encode(plain.encode(), key_multi)
        if verify(f"XOR_MULTI('{plain}')", expected_enc, actual, plain):
            tổng_pass += 1
        else:
            tổng_fail += 1

    # ===== add_rol: ADD khoá 0x05 rồi ROL shift 3 (kết hợp) =====
    print("\n=== add_rol (ADD key=0x05 rồi ROL shift=3) ===")
    tests_add_rol = [
        ([0x32, 0x8B, 0xAB, 0x6B, 0x33], "Alpha"),
        ([0x3A, 0x53, 0xCB, 0x33],       "Beta"),
    ]
    for expected_enc, plain in tests_add_rol:
        actual = add_rol_encode(plain.encode(), 0x05, 3)
        if verify(f"ADD_ROL('{plain}', 0x05, 3)", expected_enc, actual, plain):
            tổng_pass += 1
        else:
            tổng_fail += 1

    # ===== safe: kiểm tra checksum =====
    print("\n=== safe (checksum XOR) ===")
    msg = b"This is a normal message"
    cs = 0
    for b in msg:
        cs ^= b
    expected_cs = 0x25
    ok = cs == expected_cs
    tag = "PASS" if ok else "FAIL"
    print(f"  [{tag}] Checksum = 0x{cs:02X} (mong đợi 0x{expected_cs:02X})")
    if ok:
        tổng_pass += 1
    else:
        tổng_fail += 1

    # ===== Tổng kết =====
    print(f"\n=== KẾT QUẢ: {tổng_pass} đạt, {tổng_fail} lỗi ===")
    return tổng_fail == 0


if __name__ == "__main__":
    raise SystemExit(0 if main() else 1)
