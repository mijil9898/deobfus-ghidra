/*
 * safe.c — Chương trình có dùng XOR nhưng KHÔNG phải để giải mã chuỗi
 *
 * Mục đích:
 *   Kiểm thử trường hợp "dương tính giả" (false positive).
 *   Module deobfuscation sau này KHÔNG NÊN coi bất kỳ hàm nào
 *   trong file này là "hàm giải mã chuỗi".
 *
 * Các hàm có XOR nhưng KHÔNG phải giải mã:
 *   1. xor_checksum : XOR tất cả byte lại thành 1 byte kiểm tra lỗi
 *   2. xor_swap     : Hoán đổi 2 số nguyên bằng XOR (trick cổ điển)
 *   3. xor_mask_array : XOR mask lên mảng số nguyên (không phải chuỗi)
 *
 * Biên dịch:
 *   gcc -O0          -o safe_O0 safe.c
 *   gcc -O2 -s       -o safe_O2 safe.c
 *
 * Kết quả mong đợi khi chạy:
 *   Checksum: 0x25
 *   Swapped: x=99 y=42
 *   Masked: 0x21524110 0x35014541 0xEDCBA987
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>

/* ======================================================================
 * Hàm tính checksum bằng XOR
 *   - XOR tất cả byte trong mảng data lại với nhau
 *   - Kết quả là 1 byte duy nhất, KHÔNG phải chuỗi
 *   - Đây là kỹ thuật kiểm tra tính toàn vẹn dữ liệu đơn giản
 *
 * Tại sao KHÔNG phải hàm giải mã:
 *   - Đầu ra chỉ 1 byte (uint8_t), không phải buffer chuỗi
 *   - Không có tham số "key" riêng
 *   - Mục đích là tạo fingerprint, không phải khôi phục dữ liệu
 * ====================================================================== */
uint8_t xor_checksum(const unsigned char *data, int len) {
    uint8_t csum = 0;
    for (int i = 0; i < len; i++) {
        csum ^= data[i];  /* XOR dồn tất cả byte vào csum */
    }
    return csum;
}

/* ======================================================================
 * Hoán đổi 2 số nguyên bằng XOR (XOR swap trick)
 *   - Không cần biến tạm
 *   - Sau 3 bước XOR, giá trị a và b được hoán đổi
 *
 * Tại sao KHÔNG phải hàm giải mã:
 *   - Thao tác trên int, không phải mảng byte
 *   - Chỉ có 3 lệnh XOR cố định, không có vòng lặp duyệt chuỗi
 * ====================================================================== */
void xor_swap(int *a, int *b) {
    *a ^= *b;  /* bước 1: a = a XOR b */
    *b ^= *a;  /* bước 2: b = b XOR (a XOR b) = a gốc */
    *a ^= *b;  /* bước 3: a = (a XOR b) XOR a gốc = b gốc */
}

/* ======================================================================
 * XOR mask lên mảng số nguyên 32 bit
 *   - Áp dụng phép XOR với mask lên từng phần tử mảng
 *   - Dùng để biến đổi dữ liệu số, KHÔNG phải chuỗi ký tự
 *
 * Tại sao KHÔNG phải hàm giải mã:
 *   - Thao tác trên uint32_t (4 byte 1 lần), không phải từng byte
 *   - Dữ liệu đầu vào là số nguyên, không phải chuỗi mã hoá
 * ====================================================================== */
void xor_mask_array(uint32_t *arr, int count, uint32_t mask) {
    for (int i = 0; i < count; i++) {
        arr[i] ^= mask;  /* XOR từng phần tử với mask */
    }
}

int main(void) {
    /* --- Kiểm thử 1: Tính checksum chuỗi bình thường --- */
    const unsigned char msg[] = "This is a normal message";
    uint8_t cs = xor_checksum(msg, (int)strlen((const char *)msg));
    printf("Checksum: 0x%02X\n", cs);
    /* Kết quả: XOR tất cả byte của chuỗi = 0x25 */

    /* --- Kiểm thử 2: Hoán đổi 2 biến bằng XOR --- */
    int x = 42, y = 99;
    xor_swap(&x, &y);
    printf("Swapped: x=%d y=%d\n", x, y);
    /* Kết quả: x=99, y=42 (đã hoán đổi) */

    /* --- Kiểm thử 3: XOR mask lên mảng số --- */
    uint32_t data[] = {0xDEADBEEF, 0xCAFEBABE, 0x12345678};
    xor_mask_array(data, 3, 0xFFFFFFFF);
    printf("Masked: 0x%08X 0x%08X 0x%08X\n", data[0], data[1], data[2]);
    /*
     * Kết quả: mỗi số bị đảo toàn bộ bit (XOR với 0xFFFFFFFF = NOT)
     *   0xDEADBEEF ^ 0xFFFFFFFF = 0x21524110
     *   0xCAFEBABE ^ 0xFFFFFFFF = 0x35014541
     *   0x12345678 ^ 0xFFFFFFFF = 0xEDCBA987
     */

    return 0;
}
