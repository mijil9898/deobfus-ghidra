#!/usr/bin/env python3
"""
find_candidates.py — Tìm hàm giải mã ứng viên trong binary

Cách dùng:
    python3 find_candidates.py <đường_dẫn_binary>

Heuristic:
    1. Hàm có vòng lặp (while/for/do trong decompiled C)
    2. Có phép XOR / ADD / SUB / shift trên byte đơn
    3. Đọc VÀ ghi lại vào buffer byte (LOAD + STORE kích thước 1)
    4. Hàm nhỏ (< 200 Pcode ops)
    5. Không phải thunk/external
"""
import sys
import json

# Import logic phân tích Pcode từ module dùng chung
from pcode_analysis import analyze_function, find_candidates


def main():
    if len(sys.argv) < 2:
        print("Cách dùng: python3 find_candidates.py <binary>")
        sys.exit(1)

    import pyghidra
    pyghidra.start()

    from ghidra.app.decompiler import DecompInterface
    from ghidra.util.task import ConsoleTaskMonitor

    with pyghidra.open_program(sys.argv[1]) as flat_api:
        program = flat_api.getCurrentProgram()
        decompiler = DecompInterface()
        decompiler.openProgram(program)
        monitor = ConsoleTaskMonitor()

        print(f"[*] Quét {sys.argv[1]} ...", file=sys.stderr)
        candidates = find_candidates(program, decompiler, monitor)
        decompiler.dispose()

    # Loại bỏ trường func_obj (không serialize được) trước khi xuất JSON
    output_candidates = []
    for c in candidates:
        out = {k: v for k, v in c.items() if k not in ("func_obj", "entry")}
        output_candidates.append(out)

    print(json.dumps({
        "binary": sys.argv[1],
        "candidate_count": len(output_candidates),
        "candidates": output_candidates,
    }, indent=2, ensure_ascii=False))

    if candidates:
        print(f"[+] {len(candidates)} ứng viên.", file=sys.stderr)
    else:
        print("[!] Không tìm thấy ứng viên.", file=sys.stderr)


if __name__ == "__main__":
    main()
