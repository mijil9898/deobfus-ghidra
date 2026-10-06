/*
 * xor_simple.c — Mã hoá chuỗi bằng XOR với khoá 1 byte (0x41)
 *
 * Mục đích:
 *   Tạo binary kiểm thử cho module tự động tìm hàm giải mã chuỗi.
 *   Chương trình có MỘT hàm giải mã duy nhất (decode_xor), được gọi 3 lần
 *   để giải 3 chuỗi đã mã hoá sẵn trong mã nguồn.
 *
 * Cách mã hoá:
 *   Mỗi byte của chuỗi gốc được XOR với khoá 0x41.
 *   Ví dụ: 'H' = 0x48  =>  0x48 ^ 0x41 = 0x09
 *
 * Biên dịch:
 *   gcc -O0          -o xor_simple_O0     xor_simple.c  (không tối ưu, giữ symbol)
 *   gcc -O2          -o xor_simple_O2_sym xor_simple.c  (tối ưu, giữ symbol)
 *   gcc -O2 -s       -o xor_simple_O2     xor_simple.c  (tối ưu, xoá symbol)
 *
 * Kết quả mong đợi khi chạy:
 *   Hello
 *   World
 *   Secret
 */
#include <stdio.h>
#include <string.h>

/* ======================================================================
 * Hàm giải mã: XOR từng byte của mảng buf với khoá key
 *   - buf : con trỏ tới mảng byte đã mã hoá
 *   - len : số byte cần giải (không tính ký tự kết thúc '\0')
 *   - key : khoá XOR 1 byte
 * Sau khi gọi, buf chứa chuỗi đã giải mã.
 * ====================================================================== */
__attribute__((noinline, noclone))
void decode_xor(unsigned char *buf, int len, unsigned char key) {
    for (int i = 0; i < len; i++) {
        buf[i] ^= key;  /* XOR từng byte với khoá */
    }
}

int main(void) {
    /*
     * Bảng mã hoá (khoá = 0x41):
     *
     *   Ký tự gốc  | Mã ASCII | XOR 0x41 | Byte mã hoá
     *   -----------+---------+----------+------------
     *   'H'        | 0x48    | ^0x41    | 0x09
     *   'e'        | 0x65    | ^0x41    | 0x24
     *   'l'        | 0x6C    | ^0x41    | 0x2D
     *   'l'        | 0x6C    | ^0x41    | 0x2D
     *   'o'        | 0x6F    | ^0x41    | 0x2E
     *
     *   'W'        | 0x57    | ^0x41    | 0x16
     *   'o'        | 0x6F    | ^0x41    | 0x2E
     *   'r'        | 0x72    | ^0x41    | 0x33
     *   'l'        | 0x6C    | ^0x41    | 0x2D
     *   'd'        | 0x64    | ^0x41    | 0x25
     *
     *   'S'        | 0x53    | ^0x41    | 0x12
     *   'e'        | 0x65    | ^0x41    | 0x24
     *   'c'        | 0x63    | ^0x41    | 0x22
     *   'r'        | 0x72    | ^0x41    | 0x33
     *   'e'        | 0x65    | ^0x41    | 0x24
     *   't'        | 0x74    | ^0x41    | 0x35
     */

    /* Chuỗi 1: "Hello" đã mã hoá, byte cuối 0x00 là ký tự kết thúc */
    unsigned char s1[] = {0x09, 0x24, 0x2D, 0x2D, 0x2E, 0x00};

    /* Chuỗi 2: "World" đã mã hoá */
    unsigned char s2[] = {0x16, 0x2E, 0x33, 0x2D, 0x25, 0x00};

    /* Chuỗi 3: "Secret" đã mã hoá */
    unsigned char s3[] = {0x12, 0x24, 0x22, 0x33, 0x24, 0x35, 0x00};

    /* Gọi hàm giải mã 3 lần, cùng khoá 0x41 */
    decode_xor(s1, 5, 0x41);   /* giải "Hello"  */
    decode_xor(s2, 5, 0x41);   /* giải "World"  */
    decode_xor(s3, 6, 0x41);   /* giải "Secret" */

    /* In ra kết quả — nếu đúng sẽ thấy các chuỗi gốc */
    printf("%s\n", s1);  /* phải in: Hello  */
    printf("%s\n", s2);  /* phải in: World  */
    printf("%s\n", s3);  /* phải in: Secret */

    return 0;
}
