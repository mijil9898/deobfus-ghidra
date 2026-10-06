#!/usr/bin/env bash
# File này đã bị thay thế bởi check_all.sh để kiểm tra toàn diện hơn.
# Script này chỉ bọc gọi sang check_all.sh để tránh lỗi nếu bạn quen gõ lệnh cũ.

cd "$(dirname "$0")"
echo "[*] Chuyển hướng sang check_all.sh..."
exec bash check_all.sh
