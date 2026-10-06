#!/usr/bin/env python3
"""
find_candidates.py — Module 1: Tìm hàm giải mã ứng viên trong binary

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


def analyze_function(func, decompiler, monitor):
    """
    Phân tích 1 hàm bằng decompiler + Pcode.
    Trả về dict nếu là ứng viên, None nếu không.
    """
    from ghidra.program.model.pcode import PcodeOp

    result = decompiler.decompileFunction(func, 30, monitor)
    if result is None or not result.decompileCompleted():
        return None

    high_func = result.getHighFunction()
    if high_func is None:
        return None

    # --- Kiểm tra vòng lặp qua decompiled C ---
    decomp_func = result.getDecompiledFunction()  # VERIFY: DecompileResults.getDecompiledFunction()
    if decomp_func is None:
        return None
    c_code = decomp_func.getC()  # VERIFY: DecompiledFunction.getC()
    if not c_code:
        return None

    has_loop = ("while" in c_code or "for (" in c_code or "do {" in c_code)
    if not has_loop:
        return None

    # --- Phân tích Pcode ---
    has_xor = False
    has_add_sub = False
    has_shift = False
    has_or = False
    has_byte_store = False
    has_byte_load = False
    op_count = 0

    pcode_iter = high_func.getPcodeOps()  # VERIFY: HighFunction.getPcodeOps()
    while pcode_iter.hasNext():
        op = pcode_iter.next()
        op_count += 1
        opcode = op.getOpcode()

        if opcode == PcodeOp.INT_XOR:
            has_xor = True
        elif opcode in (PcodeOp.INT_ADD, PcodeOp.INT_SUB):
            has_add_sub = True
        elif opcode in (PcodeOp.INT_LEFT, PcodeOp.INT_RIGHT):  # VERIFY: INT_LEFT, INT_RIGHT
            has_shift = True
        elif opcode == PcodeOp.INT_OR:
            has_or = True

        if opcode == PcodeOp.STORE:
            val = op.getInput(2)
            if val is not None and val.getSize() == 1:
                has_byte_store = True
        if opcode == PcodeOp.LOAD:
            out = op.getOutput()
            if out is not None and out.getSize() == 1:
                has_byte_load = True

    # --- Lọc ---
    has_crypto = has_xor or (has_shift and has_or)
    if not has_crypto and not (has_add_sub and has_byte_store):
        return None
    if not has_byte_store or not has_byte_load:
        return None
    if op_count > 200:
        return None

    # --- Đoán thuật toán ---
    if has_xor and not has_shift:
        algo = "xor"
    elif has_shift and has_or and has_add_sub:
        algo = "add_rol"
    elif has_shift and has_or:
        algo = "rol"
    elif has_add_sub and not has_xor:
        algo = "add"
    else:
        algo = "unknown"

    return {
        "name": func.getName(),
        "entry_offset": "0x{:x}".format(func.getEntryPoint().getOffset()),
        "algorithm_guess": algo,
        "param_count": func.getParameterCount(),
        "pcode_ops": op_count,
        "features": {
            "xor": has_xor, "add_sub": has_add_sub,
            "shift": has_shift, "or": has_or,
            "byte_store": has_byte_store, "byte_load": has_byte_load,
        },
    }


def find_candidates(program, decompiler, monitor):
    """Quét tất cả hàm, trả về danh sách ứng viên."""
    candidates = []
    for func in program.getFunctionManager().getFunctions(True):
        if func.isThunk() or func.isExternal():
            continue
        info = analyze_function(func, decompiler, monitor)
        if info is not None:
            candidates.append(info)
    return candidates


def main():
    if len(sys.argv) < 2:
        print("Cách dùng: python3 find_candidates.py <binary>")
        sys.exit(1)

    import pyghidra
    pyghidra.start()

    from ghidra.app.decompiler import DecompInterface
    from ghidra.util.task import ConsoleTaskMonitor  # VERIFY: import path

    with pyghidra.open_program(sys.argv[1]) as flat_api:  # VERIFY: open_program
        program = flat_api.getCurrentProgram()
        decompiler = DecompInterface()
        decompiler.openProgram(program)
        monitor = ConsoleTaskMonitor()

        print(f"[*] Quét {sys.argv[1]} ...", file=sys.stderr)
        candidates = find_candidates(program, decompiler, monitor)
        decompiler.dispose()

    print(json.dumps({
        "binary": sys.argv[1],
        "candidate_count": len(candidates),
        "candidates": candidates,
    }, indent=2, ensure_ascii=False))

    if candidates:
        print(f"[+] {len(candidates)} ứng viên.", file=sys.stderr)
    else:
        print("[!] Không tìm thấy ứng viên.", file=sys.stderr)


if __name__ == "__main__":
    main()
