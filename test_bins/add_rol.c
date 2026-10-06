/*
 * add_rol.c — Mã hoá chuỗi bằng ADD rồi ROL (2 bước, 1 hàm duy nhất)
 *
 * Mục đích:
 *   Kiểm thử thuật toán mã hoá kết hợp (không phải XOR đơn thuần).
 *   Chỉ có MỘT hàm giải mã duy nhất: decode_add_rol.
 *
 * Quy trình mã hoá (2 bước cho mỗi byte):
 *   Bước 1 — ADD: byte_tạm = byte_gốc + key_add       (mod 256)
 *   Bước 2 — ROL: byte_mã  = ROL(byte_tạm, shift_rol)
 *     Trong đó ROL(x, n) = (x << n) | (x >> (8 - n))   (xoay trái n bit)
 *
 * Quy trình giải mã (đảo ngược, 2 bước):
 *   Bước 1 — ROR: byte_tạm = ROR(byte_mã, shift_rol)   (xoay phải)
 *   Bước 2 — SUB: byte_gốc = byte_tạm - key_add
 *
 * Ví dụ chi tiết cho ký tự 'A' (key_add=0x05, shift_rol=3):
 *   Mã hoá: 'A'=0x41 → +0x05=0x46 → ROL3=0x32
 *     0x46 = 0100_0110
 *     ROL3: (0x46 << 3) & 0xFF = 0x30
 *            (0x46 >> 5)        = 0x02
 *            0x30 | 0x02        = 0x32
 *   Giải mã: 0x32 → ROR3=0x46 → -0x05=0x41='A' ✓
 *
 * Biên dịch:
 *   gcc -O0          -o add_rol_O0     add_rol.c
 *   gcc -O2          -o add_rol_O2_sym add_rol.c
 *   gcc -O2 -s       -o add_rol_O2     add_rol.c
 *
 * Kết quả mong đợi khi chạy:
 *   Alpha
 *   Beta
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>

/* ======================================================================
 * Hàm giải mã duy nhất: decode_add_rol
 *   Đảo ngược quy trình mã hoá ADD+ROL cho từng byte:
 *     1. Xoay phải (ROR) để đảo ngược bước ROL khi mã hoá
 *     2. Trừ khoá (SUB) để đảo ngược bước ADD khi mã hoá
 *
 * Tham số:
 *   - buf       : mảng byte đã mã hoá (sẽ bị ghi đè bằng kết quả giải mã)
 *   - len       : số byte cần giải (không tính '\0')
 *   - key_add   : khoá ADD 1 byte (đã dùng khi mã hoá)
 *   - shift_rol : số bit đã xoay trái khi mã hoá
 * ====================================================================== */
__attribute__((noinline, noclone))
void decode_add_rol(unsigned char *buf, int len,
                    unsigned char key_add, int shift_rol) {
    for (int i = 0; i < len; i++) {
        uint8_t b = buf[i];
        /* Bước 1: ROR — đảo ngược ROL */
        b = (uint8_t)((b >> shift_rol) | (b << (8 - shift_rol)));
        /* Bước 2: SUB — đảo ngược ADD */
        b -= key_add;
        buf[i] = b;
    }
}

int main(void) {
    /*
     * === Chuỗi 1: "Alpha" ===
     * Mã hoá: ADD key=0x05, rồi ROL shift=3
     *
     *   Ký tự | ASCII | +0x05 (ADD) | ROL 3 bit    | Byte mã hoá
     *   ------+-------+-------------+--------------+------------
     *   'A'   | 0x41  | 0x46        | 0011_0010    | 0x32
     *   'l'   | 0x6C  | 0x71        | 1000_1011    | 0x8B
     *   'p'   | 0x70  | 0x75        | 1010_1011    | 0xAB
     *   'h'   | 0x68  | 0x6D        | 0110_1011    | 0x6B
     *   'a'   | 0x61  | 0x66        | 0011_0011    | 0x33
     */
    unsigned char s1[] = {0x32, 0x8B, 0xAB, 0x6B, 0x33, 0x00};

    /*
     * === Chuỗi 2: "Beta" ===
     * Mã hoá: ADD key=0x05, rồi ROL shift=3
     *
     *   Ký tự | ASCII | +0x05 (ADD) | ROL 3 bit    | Byte mã hoá
     *   ------+-------+-------------+--------------+------------
     *   'B'   | 0x42  | 0x47        | 0011_1010    | 0x3A
     *   'e'   | 0x65  | 0x6A        | 0101_0011    | 0x53
     *   't'   | 0x74  | 0x79        | 1100_1011    | 0xCB
     *   'a'   | 0x61  | 0x66        | 0011_0011    | 0x33
     */
    unsigned char s2[] = {0x3A, 0x53, 0xCB, 0x33, 0x00};

    /* Giải mã cả 2 chuỗi: ROR rồi SUB */
    decode_add_rol(s1, 5, 0x05, 3);  /* giải "Alpha" */
    decode_add_rol(s2, 4, 0x05, 3);  /* giải "Beta"  */

    /* In kết quả */
    printf("%s\n", s1);  /* phải in: Alpha */
    printf("%s\n", s2);  /* phải in: Beta  */

    return 0;
}
