#!/usr/bin/env python3
"""
pcode_analysis.py — Module phân tích Pcode dùng chung

Chứa logic nhận diện hàm giải mã ứng viên (heuristic Pcode),
được import bởi ghidra_auto.py và find_candidates.py.

Lưu ý: các import từ ghidra.* chỉ hoạt động sau pyghidra.start(),
nên PHẢI nằm trong thân hàm, không đưa lên đầu file.
"""


def pcode_flags(hf):
    """Phân tích Pcode ops trong high function, trả về dict cờ đặc trưng."""
    from ghidra.program.model.pcode import PcodeOp

    f = dict(
        xor=False, add_sub=False, shift=False, or_=False,
        byte_store=False, byte_load=False, int_rem=False, op_count=0,
    )
    it = hf.getPcodeOps()
    while it.hasNext():
        op = it.next()
        f["op_count"] += 1
        opc = op.getOpcode()
        if opc == PcodeOp.INT_XOR:
            f["xor"] = True
        elif opc in (PcodeOp.INT_ADD, PcodeOp.INT_SUB):
            f["add_sub"] = True
        elif opc in (PcodeOp.INT_LEFT, PcodeOp.INT_RIGHT, PcodeOp.INT_SRIGHT):
            f["shift"] = True
        elif opc == PcodeOp.INT_OR:
            f["or_"] = True
        elif opc in (PcodeOp.INT_REM, PcodeOp.INT_SREM):
            f["int_rem"] = True
        elif opc == PcodeOp.STORE:
            v = op.getInput(2)
            if v and v.getSize() == 1:
                f["byte_store"] = True
        elif opc == PcodeOp.LOAD:
            o = op.getOutput()
            if o and o.getSize() == 1:
                f["byte_load"] = True
    return f


def guess_algo(f):
    """Đoán thuật toán mã hoá dựa trên cờ Pcode."""
    # XOR nhiều byte: có phép chia lấy dư (i % keylen)
    if f["xor"] and f["int_rem"]:
        return "xor_multi"
    if f["xor"] and not f["shift"]:
        return "xor"
    if f["shift"] and f["or_"] and f["add_sub"]:
        return "add_rol"
    if f["shift"] and f["or_"]:
        return "rol"
    if f["add_sub"] and not f["xor"]:
        return "add"
    return "unknown"


def analyze_function(func, decompiler, monitor):
    """
    Phân tích 1 hàm bằng decompiler + Pcode.
    Trả về dict nếu là ứng viên hàm giải mã, None nếu không.
    """
    result = decompiler.decompileFunction(func, 30, monitor)
    if result is None or not result.decompileCompleted():
        return None
    hf = result.getHighFunction()
    if hf is None:
        return None
    df = result.getDecompiledFunction()
    if df is None:
        return None
    c = df.getC() or ""
    if not any(k in c for k in ("while", "for (", "do {")):
        return None
    f = pcode_flags(hf)
    if f["op_count"] > 200:
        return None
    if not (f["byte_store"] and f["byte_load"]):
        return None
    if not f["xor"] and not (f["shift"] and f["or_"]):
        return None
    algo = guess_algo(f)
    return dict(
        func_obj=func,
        name=func.getName(),
        entry=func.getEntryPoint(),
        entry_offset="0x{:x}".format(func.getEntryPoint().getOffset()),
        algorithm=algo,
        pcode_ops=f["op_count"],
    )


def find_candidates(program, decompiler, monitor):
    """Quét tất cả hàm, trả về danh sách ứng viên hàm giải mã."""
    candidates = []
    for func in program.getFunctionManager().getFunctions(True):
        if func.isThunk() or func.isExternal():
            continue
        info = analyze_function(func, decompiler, monitor)
        if info is not None:
            candidates.append(info)
    return candidates
