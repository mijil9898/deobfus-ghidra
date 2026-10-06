#!/usr/bin/env bash
# ==============================================================================
# check_all.sh — Module 0.1: Kiểm tra tổng hợp và sinh expected_addresses.json
#
# Cách dùng: bash check_all.sh
# ==============================================================================
set -euo pipefail
cd "$(dirname "$0")"

SOURCES=("xor_simple" "xor_multibyte" "add_rol" "safe")

PASS=0
FAIL=0

echo "=== DỌN DẸP RÁC CŨ ==="
# Xoá các file binary cũ bị vương vãi ở thư mục hiện tại
rm -f *_O0 *_O2 *_O2_sym 2>/dev/null || true
mkdir -p bin
echo "  [PASS] Đã tạo thư mục bin/ để gom file binary"

echo ""
echo "=== (a) BIÊN DỊCH ==="
for src in "${SOURCES[@]}"; do
    if gcc -O0 -o "bin/${src}_O0" "${src}.c" && \
       gcc -O2 -o "bin/${src}_O2_sym" "${src}.c" && \
       gcc -O2 -s -o "bin/${src}_O2" "${src}.c"; then
        echo "  [PASS] Biên dịch ${src} (O0, O2_sym, O2) vào bin/"
        PASS=$((PASS + 1))
    else
        echo "  [FAIL] Biên dịch ${src}"
        FAIL=$((FAIL + 1))
    fi
done

# Hàm tiện ích in kết quả
check() {
    local ok="$1" label="$2" err_msg="$3"
    if [ "$ok" -eq 1 ]; then
        echo "  [PASS] $label"
        PASS=$((PASS + 1))
    else
        echo "  [FAIL] $label"
        echo "    Lỗi: $err_msg"
        FAIL=$((FAIL + 1))
    fi
}

echo ""
echo "=== (b) CHẠY KIỂM TRA ĐẦU RA ==="
EXPECT_xor_simple=$'Hello\nWorld\nSecret'
EXPECT_xor_multibyte=$'OpenAI\nGhidra'
EXPECT_add_rol=$'Alpha\nBeta'
EXPECT_safe=$'Checksum: 0x25\nSwapped: x=99 y=42\nMasked: 0x21524110 0x35014541 0xEDCBA987'

for src in "${SOURCES[@]}"; do
    eval "expected=\$EXPECT_${src}"
    for opt in O0 O2_sym O2; do
        bin="bin/${src}_${opt}"
        actual=$("./${bin}" || true)
        if [ "$actual" = "$expected" ]; then
            check 1 "Đầu ra ${bin}" ""
        else
            check 0 "Đầu ra ${bin}" "Không khớp mong đợi.\nThực tế:\n$actual"
        fi
    done
done

echo ""
echo "=== (c) KIỂM TRA LỘ CHUỖI GỐC (strings) ==="
# Danh sách các chuỗi cần giấu
SECRET_STRINGS=("Hello" "World" "Secret" "OpenAI" "Ghidra" "Alpha" "Beta")
for src in "${SOURCES[@]}"; do
    if [ "$src" = "safe" ]; then continue; fi # Safe không có chuỗi bí mật
    for opt in O0 O2_sym O2; do
        bin="bin/${src}_${opt}"
        found=""
        for sec in "${SECRET_STRINGS[@]}"; do
            if strings "${bin}" | grep -q "${sec}"; then
                found="${found} ${sec}"
            fi
        done
        if [ -z "$found" ]; then
            check 1 "Không lộ chuỗi: ${bin}" ""
        else
            check 0 "Lộ chuỗi: ${bin}" "Tìm thấy chuỗi rõ: $found"
        fi
    done
done

echo ""
echo "=== (d) KIỂM TRA TỒN TẠI HÀM GIẢI MÃ (nm) ==="
# Map tên hàm giải mã cho từng file
FUNC_xor_simple="decode_xor"
FUNC_xor_multibyte="decode_xor_multi"
FUNC_add_rol="decode_add_rol"

for src in "${SOURCES[@]}"; do
    if [ "$src" = "safe" ]; then continue; fi
    eval "func_name=\$FUNC_${src}"
    
    for opt in O0 O2_sym; do
        bin="bin/${src}_${opt}"
        if nm "${bin}" 2>/dev/null | grep -q " ${func_name}$"; then
            check 1 "Tìm thấy ${func_name} trong ${bin}" ""
        else
            check 0 "Không tìm thấy ${func_name} trong ${bin}" "Bị inline/xóa?"
        fi
    done
done

echo ""
echo "=== (e) KIỂM TRA STRIPPED (no symbols) ==="
for src in "${SOURCES[@]}"; do
    bin="bin/${src}_O2"
    # nm trên file stripped sẽ báo "no symbols" hoặc trả về rỗng / lỗi
    if nm "${bin}" 2>&1 | grep -qi "no symbols"; then
         check 1 "${bin} đã bị strip" ""
    elif [ -z "$(nm "${bin}" 2>/dev/null)" ]; then
         check 1 "${bin} đã bị strip (rỗng)" ""
    else
         check 0 "${bin} chưa bị strip hoàn toàn" "nm vẫn trả về symbol"
    fi
done

echo ""
echo "=== (f) KIỂM TRA SAFE.C ==="
# Phải đảm bảo không có hàm nào trong safe.c có từ khóa "decode" trong tên
for opt in O0 O2_sym; do
    bin="bin/safe_${opt}"
    if nm "${bin}" 2>/dev/null | grep -qi "decode"; then
        check 0 "${bin} có chứa hàm tên giống giải mã" ""
    else
        check 1 "${bin} an toàn (không có hàm giải mã)" ""
    fi
done

echo ""
echo "=== TẠO expected_addresses.json ==="
ADDR_FILE="expected_addresses.json"
echo '{' > "$ADDR_FILE"
echo '  "note": "Địa chỉ vào (entry) của hàm giải mã lấy từ bản có symbol bằng lệnh nm. Với bản stripped (O2), hãy nạp bản O2_sym cùng lần biên dịch vào Ghidra để tìm địa chỉ, vì O2 và O2_sym chia sẻ layout bộ nhớ hoàn toàn giống nhau.",' >> "$ADDR_FILE"

is_first=1
for src in "${SOURCES[@]}"; do
    if [ "$src" = "safe" ]; then continue; fi
    eval "func_name=\$FUNC_${src}"
    
    if [ $is_first -eq 0 ]; then echo "  ," >> "$ADDR_FILE"; fi
    is_first=0
    
    echo "  \"${src}\": {" >> "$ADDR_FILE"
    
    # Hàm con để lấy addr
    get_addr() {
        local b="$1" f="$2"
        # Cắt lấy cột đầu tiên (địa chỉ hex)
        nm "$b" 2>/dev/null | grep " ${f}$" | awk '{print $1}' | sed 's/^0*//'
    }
    
    addr_O0=$(get_addr "bin/${src}_O0" "$func_name")
    addr_O2_sym=$(get_addr "bin/${src}_O2_sym" "$func_name")
    
    # Bổ sung 0x nếu không rỗng
    [ -n "$addr_O0" ] && addr_O0="0x${addr_O0}" || addr_O0="NOT_FOUND"
    [ -n "$addr_O2_sym" ] && addr_O2_sym="0x${addr_O2_sym}" || addr_O2_sym="NOT_FOUND"
    
    echo "    \"O0\": \"$addr_O0\"," >> "$ADDR_FILE"
    echo "    \"O2_sym\": \"$addr_O2_sym\"," >> "$ADDR_FILE"
    echo "    \"O2_stripped_reference\": \"$addr_O2_sym\"" >> "$ADDR_FILE"
    echo "  }" >> "$ADDR_FILE"
done
echo '}' >> "$ADDR_FILE"
echo "  [PASS] Đã sinh $ADDR_FILE"
PASS=$((PASS + 1))

echo ""
echo "=================================================="
echo "KẾT QUẢ TỔNG HỢP: ${PASS} đạt, ${FAIL} lỗi"
echo "=================================================="

if [ "$FAIL" -gt 0 ]; then
    exit 1
else
    exit 0
fi
