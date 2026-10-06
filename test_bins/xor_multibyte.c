/*
 * xor_multibyte.c — Mã hoá chuỗi bằng XOR với khoá NHIỀU byte
 *
 * Mục đích:
 *   Kiểm thử trường hợp khoá dài hơn 1 byte.
 *   Khoá {0xDE, 0xAD, 0xBE, 0xEF} được lặp vòng (cyclic) qua từng byte
 *   của chuỗi gốc.
 *
 * Cách mã hoá:
 *   byte_mã_hoá[i] = byte_gốc[i] XOR khoá[i % độ_dài_khoá]
 *   Ví dụ: chuỗi "OpenAI", khoá 4 byte:
 *     O ^ DE = 91     (vị trí 0, dùng khoá[0])
 *     p ^ AD = DD     (vị trí 1, dùng khoá[1])
 *     e ^ BE = DB     (vị trí 2, dùng khoá[2])
 *     n ^ EF = 81     (vị trí 3, dùng khoá[3])
 *     A ^ DE = 9F     (vị trí 4, quay lại khoá[0])
 *     I ^ AD = E4     (vị trí 5, quay lại khoá[1])
 *
 * Biên dịch:
 *   gcc -O0          -o xor_multibyte_O0     xor_multibyte.c
 *   gcc -O2          -o xor_multibyte_O2_sym xor_multibyte.c
 *   gcc -O2 -s       -o xor_multibyte_O2     xor_multibyte.c
 *
 * Kết quả mong đợi khi chạy:
 *   OpenAI
 *   Ghidra
 */
#include <stdio.h>
#include <string.h>

/* ======================================================================
 * Hàm giải mã: XOR từng byte với khoá nhiều byte (lặp vòng)
 *   - buf    : con trỏ tới mảng byte đã mã hoá
 *   - len    : số byte cần giải
 *   - key    : con trỏ tới mảng khoá
 *   - keylen : độ dài khoá (số byte)
 *
 * Công thức giải: buf[i] = buf[i] XOR key[i % keylen]
 * Phép XOR tự nghịch đảo nên mã hoá và giải mã cùng một hàm.
 * ====================================================================== */
__attribute__((noinline, noclone))
void decode_xor_multi(unsigned char *buf, int len,
                       const unsigned char *key, int keylen) {
    for (int i = 0; i < len; i++) {
        buf[i] ^= key[i % keylen];  /* XOR với byte khoá tương ứng */
    }
}

int main(void) {
    /* Khoá 4 byte */
    unsigned char key[] = {0xDE, 0xAD, 0xBE, 0xEF};

    /*
     * Bảng mã hoá cho "OpenAI" (khoá = DE AD BE EF):
     *
     *   Vị trí | Ký tự | ASCII | Khoá | Kết quả
     *   -------+-------+-------+------+--------
     *     0    |  'O'  | 0x4F  | 0xDE | 0x91
     *     1    |  'p'  | 0x70  | 0xAD | 0xDD
     *     2    |  'e'  | 0x65  | 0xBE | 0xDB
     *     3    |  'n'  | 0x6E  | 0xEF | 0x81
     *     4    |  'A'  | 0x41  | 0xDE | 0x9F
     *     5    |  'I'  | 0x49  | 0xAD | 0xE4
     */
    unsigned char s1[] = {0x91, 0xDD, 0xDB, 0x81, 0x9F, 0xE4, 0x00};

    /*
     * Bảng mã hoá cho "Ghidra" (khoá = DE AD BE EF):
     *
     *   Vị trí | Ký tự | ASCII | Khoá | Kết quả
     *   -------+-------+-------+------+--------
     *     0    |  'G'  | 0x47  | 0xDE | 0x99
     *     1    |  'h'  | 0x68  | 0xAD | 0xC5
     *     2    |  'i'  | 0x69  | 0xBE | 0xD7
     *     3    |  'd'  | 0x64  | 0xEF | 0x8B
     *     4    |  'r'  | 0x72  | 0xDE | 0xAC
     *     5    |  'a'  | 0x61  | 0xAD | 0xCC
     */
    unsigned char s2[] = {0x99, 0xC5, 0xD7, 0x8B, 0xAC, 0xCC, 0x00};

    /* Giải mã cả 2 chuỗi */
    decode_xor_multi(s1, 6, key, 4);  /* giải "OpenAI" */
    decode_xor_multi(s2, 6, key, 4);  /* giải "Ghidra" */

    /* In kết quả */
    printf("%s\n", s1);  /* phải in: OpenAI */
    printf("%s\n", s2);  /* phải in: Ghidra */

    return 0;
}
