#!/usr/bin/env python3
"""
ghidra_auto.py — Tự động tìm hàm giải mã chuỗi và giải mã chuỗi trong binary

Sử dụng PyGhidra để phân tích binary, tìm hàm giải mã ứng viên bằng heuristic Pcode,
trích xuất chuỗi đã mã hoá từ C decompiled, và giải mã chúng.

Thuật toán hỗ trợ: xor (1 byte), xor_multi (nhiều byte), add, add_rol, rol.
"""
import re, sys, json, warnings, argparse
from collections import defaultdict
warnings.filterwarnings("ignore", category=DeprecationWarning)

# Import Module 1 (phân tích Pcode tìm hàm giải mã) từ module dùng chung
from pcode_analysis import find_candidates


# === MODULE 2a: NHÓM ĐIỂM GỌI THEO CALLER ===
def get_calls_by_caller(program, entry):
    """Nhóm các điểm gọi tới hàm tại ``entry`` theo hàm caller."""
    res = defaultdict(list)
    for ref in program.getReferenceManager().getReferencesTo(entry):
        if not ref.getReferenceType().isCall():
            continue
        addr = ref.getFromAddress()
        caller = program.getFunctionManager().getFunctionContaining(addr)
        if caller:
            res[caller].append(addr)
    return res


# === MODULE 2b: TIỆN ÍCH PARSE C DECOMPILED ===
def _parse_c_str(s):
    """Phân tích chuỗi C escape (\\x, \\n, \\t, …) thành bytes."""
    out = bytearray(); i = 0
    while i < len(s):
        if s[i] != "\\":
            out.append(ord(s[i])); i += 1; continue
        i += 1
        if i >= len(s):
            break
        c = s[i]
        if c == "x" and i + 2 < len(s):
            try:
                out.append(int(s[i+1:i+3], 16)); i += 3
            except ValueError:
                out.append(ord("x")); i += 1
        elif c == "n":  out.append(10); i += 1
        elif c == "t":  out.append(9);  i += 1
        elif c == "r":  out.append(13); i += 1
        elif c == "0":  out.append(0);  i += 1
        elif c == "\\": out.append(92); i += 1
        elif c == '"':  out.append(34); i += 1
        else:           out.append(ord(c)); i += 1
    return bytes(out)


def _nws(e):
    """Xoá toàn bộ khoảng trắng trong chuỗi."""
    return re.sub(r"\s+", "", e)


def _lam_sach_bieu_thuc(bieu_thuc):
    """Loại bỏ ép kiểu cast (char *), (undefined1 *) và toán tử lấy địa chỉ & trong C decompiled."""
    bt = re.sub(r'\([^)]+\)', '', bieu_thuc)
    return bt.strip().lstrip('&').strip()


def _tim_buffer(dest, dest_clean, buf_map, stack_read_fn, do_dai):
    """Tìm buffer dữ liệu mã hoá từ buf_map hoặc stack model."""
    raw = buf_map.get(dest) or buf_map.get(dest_clean)
    if raw is None:
        m_off = re.match(r'^([A-Za-z0-9_]+)\+([x0-9a-fA-F]+)$', dest_clean)
        if m_off:
            base = m_off.group(1)
            try:
                offset = int(m_off.group(2), 0)
                if base in buf_map:
                    raw = buf_map[base][offset:]
            except (ValueError, IndexError):
                pass
    if raw is None:
        raw = stack_read_fn(dest, do_dai)
    if raw is None:
        for bk, bv in buf_map.items():
            if dest_clean.startswith(bk) or bk.startswith(dest_clean):
                raw = bv
                break
    return raw


def extract_strings_from_c(c_code, func_name, algo):
    """
    Trích xuất chuỗi mã hoá từ C decompiled và giải mã chúng.

    Trả về: (danh_sách_kết_quả, last_key)
    Mỗi kết quả chứa: dest, dest_src, length, status, và decoded (nếu thành công).
    """
    results = []; last_key = None
    aliases = {}
    for m in re.finditer(r"^\s*(\w+)\s*=\s*([\w\s\+\-x0-9_]+?)\s*;", c_code, re.M):
        aliases[m.group(1).strip()] = m.group(2).strip()

    def resolve(e):
        e = e.strip()
        return aliases.get(e, e)

    buf_map = {}

    # --- builtin_strncpy ---
    pat_cpy = re.compile(r'builtin_strncpy\s*\(\s*([^,]+?)\s*,\s*"((?:[^"\\]|\\.)*)"\s*', re.S)
    for m in pat_cpy.finditer(c_code):
        dest = _nws(resolve(m.group(1))); raw = _parse_c_str(m.group(2))
        buf_map[dest] = raw
        print(f"  [parse] strncpy {dest!r} = {raw.hex()}", file=sys.stderr)

    # --- Gán từng phần tử mảng: dest[idx] = val; ---
    array_assignments = defaultdict(dict)
    pat_assign = re.compile(r'^\s*([A-Za-z0-9_]+)\[(\d+)\]\s*=\s*(.+?)\s*;', re.M)
    for m in pat_assign.finditer(c_code):
        base, idx, val_str = _nws(m.group(1)), int(m.group(2)), m.group(3).strip()
        if val_str.startswith("'") and val_str.endswith("'"):
            ch = val_str[1:-1]
            if ch.startswith('\\'):
                if   ch == '\\0':    val = 0
                elif ch == '\\n':    val = 10
                elif ch == '\\t':    val = 9
                elif ch == '\\r':    val = 13
                elif ch == '\\"':    val = 34
                elif ch == '\\\\':   val = 92
                else:                val = ord(ch[-1])
            else:
                val = ord(ch)
        elif val_str.startswith("0x") or val_str.startswith("-0x"):
            val = int(val_str, 16)
        else:
            try:
                val = int(val_str)
            except ValueError:
                val = 0
        array_assignments[base][idx] = val & 0xFF

    for base, byte_dict in array_assignments.items():
        if not byte_dict:
            continue
        max_idx = max(byte_dict.keys())
        buf = bytearray(max_idx + 1)
        for idx, val in byte_dict.items():
            buf[idx] = val
        buf_map[base] = bytes(buf)
        print(f"  [parse] array {base!r} = {bytes(buf).hex()}", file=sys.stderr)

    # --- Stack model: ghidra "local_XX", "uStack_XX", "acStack_XX"… = vị trí -0xXX ---
    # Gom byte từ strncpy + gán số nguyên
    def _stk(ten):
        ten_sach = _lam_sach_bieu_thuc(ten)
        m = re.fullmatch(r"(?:local_|[a-zA-Z]*Stack_|stack_?)([0-9a-fA-F]+)", ten_sach)
        return -int(m.group(1), 16) if m else None

    mem = {}
    for bk, bv in buf_map.items():
        a = _stk(bk)
        if a is not None:
            for j, b in enumerate(bv):
                mem[a + j] = b

    tsize = {"undefined": 1, "undefined1": 1, "undefined2": 2, "undefined4": 4, "undefined8": 8,
             "byte": 1, "char": 1, "short": 2, "ushort": 2, "int": 4, "uint": 4,
             "long": 8, "ulong": 8, "longlong": 8, "ulonglong": 8}
    vsize = {}
    for m in re.finditer(r"^\s*(?:unsigned\s+)?(\w+)\s+((?:local_|[a-zA-Z]*Stack_|stack_?)[0-9a-fA-F]+)\s*;", c_code, re.M):
        if m.group(1) in tsize:
            vsize[m.group(2)] = tsize[m.group(1)]

    for m in re.finditer(r"^\s*((?:local_|[a-zA-Z]*Stack_|stack_?)[0-9a-fA-F]+)\s*=\s*(-?0x[0-9a-fA-F]+|\d+)U?L{0,2}\s*;", c_code, re.M):
        a = _stk(m.group(1)); sz = vsize.get(m.group(1))
        if a is None or not sz:
            continue
        v = int(m.group(2), 0) & ((1 << (8 * sz)) - 1)
        for j, b in enumerate(v.to_bytes(sz, "little")):
            mem[a + j] = b
        print(f"  [parse] scalar {m.group(1)!r} = {v:0{sz*2}x} ({sz}B)", file=sys.stderr)

    def stack_read(dich, do_dai):
        dich_sach = _lam_sach_bieu_thuc(dich)
        m = re.fullmatch(r"((?:local_|[a-zA-Z]*Stack_|stack_?)[0-9a-fA-F]+)(?:\+(\w+))?", dich_sach)
        if not m:
            return None
        a = _stk(m.group(1))
        if a is None:
            return None
        if m.group(2):
            try:
                a += int(m.group(2), 0)
            except ValueError:
                return None
        if all(a + j in mem for j in range(do_dai)):
            return bytes(mem[a + j] for j in range(do_dai))
        return None

    # --- Tìm các lời gọi tới hàm giải mã trong C code ---
    pat_dec = re.compile(r"\b" + re.escape(func_name) + r"\s*\(\s*([^)]+)\)\s*;", re.S)
    for m in pat_dec.finditer(c_code):
        args = [a.strip() for a in m.group(1).split(",")]
        if len(args) < 2:
            continue
        dest_raw = resolve(args[0])
        dest = _nws(dest_raw)
        dest_clean = _nws(_lam_sach_bieu_thuc(dest_raw))
        dest_src = _nws(args[0])  # Tên gốc trong C (chưa resolve alias)
        try:
            length = int(resolve(args[1]).strip(), 0)
        except ValueError:
            continue

        if algo == "xor_multi":
            # Tham số: (buf, len, key_ptr, keylen)
            if len(args) < 4:
                results.append(dict(dest=dest, dest_src=dest_src, length=length,
                                    status="thiếu_tham_số_key"))
                continue
            key_ptr_raw = resolve(args[2])
            key_ptr = _nws(_lam_sach_bieu_thuc(key_ptr_raw))
            try:
                keylen = int(resolve(args[3]).strip(), 0)
            except ValueError:
                results.append(dict(dest=dest, dest_src=dest_src, length=length,
                                    status="keylen_unknown"))
                continue
            # Lấy key bytes từ buf_map hoặc stack model
            key_bytes = buf_map.get(key_ptr) or stack_read(key_ptr_raw, keylen)
            if key_bytes is None:
                for bk, bv in buf_map.items():
                    if key_ptr.startswith(bk) or bk.startswith(key_ptr):
                        key_bytes = bv; break
            if key_bytes is None:
                results.append(dict(dest=dest, dest_src=dest_src, length=length,
                                    status="key_buf_not_found"))
                continue
            key_bytes = key_bytes[:keylen]
            raw = _tim_buffer(dest, dest_clean, buf_map, stack_read, length)
            if raw is None:
                results.append(dict(dest=dest, dest_src=dest_src, length=length,
                                    status="buf_not_found"))
                continue
            try:
                decoded = run_decode("xor_multi", raw[:length], key_bytes)
            except Exception as e:
                decoded = f"<lỗi:{e}>"
            results.append(dict(dest=dest, dest_src=dest_src, length=length,
                                key_hex=key_bytes.hex(), raw_hex=raw[:length].hex(),
                                decoded=decoded, status="ok"))

        elif algo == "add_rol":
            # Tham số: (buf, len, key_add, shift_rol)
            if len(args) >= 3:
                try:
                    last_key = int(resolve(args[2]).strip(), 0)
                except ValueError:
                    last_key = None
                    print(f"      [!] không parse được key {args[2]!r}", file=sys.stderr)
            key = last_key
            if key is None:
                results.append(dict(dest=dest, dest_src=dest_src, length=length,
                                    status="key_unknown"))
                continue
            # Đọc shift_rol từ tham số thứ 4 (bắt buộc, không đoán)
            if len(args) >= 4:
                try:
                    shift_val = int(resolve(args[3]).strip(), 0)
                except ValueError:
                    results.append(dict(dest=dest, dest_src=dest_src, length=length,
                                        key=hex(key), status="shift_unknown"))
                    continue
            else:
                results.append(dict(dest=dest, dest_src=dest_src, length=length,
                                    key=hex(key), status="shift_unknown"))
                continue
            raw = _tim_buffer(dest, dest_clean, buf_map, stack_read, length)
            if raw is None:
                results.append(dict(dest=dest, dest_src=dest_src, length=length,
                                    key=hex(key), status="buf_not_found"))
                continue
            try:
                decoded = run_decode("add_rol", raw[:length], key, shift=shift_val)
            except Exception as e:
                decoded = f"<lỗi:{e}>"
            results.append(dict(dest=dest, dest_src=dest_src, length=length,
                                key=hex(key), shift=shift_val, raw_hex=raw[:length].hex(),
                                decoded=decoded, status="ok"))

        else:
            # xor, add, unknown — logic chuẩn
            if len(args) >= 3:
                try:
                    last_key = int(resolve(args[2]).strip(), 0)
                except ValueError:
                    # Tham số key có mặt nhưng không đọc được (vd 'Z', (char)0x5a): không dùng lại khoá cũ.
                    last_key = None
                    print(f"      [!] không parse được key {args[2]!r}", file=sys.stderr)
            key = last_key
            if key is None:
                results.append(dict(dest=dest, dest_src=dest_src, length=length,
                                    status="key_unknown"))
                continue
            raw = _tim_buffer(dest, dest_clean, buf_map, stack_read, length)
            if raw is None:
                results.append(dict(dest=dest, dest_src=dest_src, length=length,
                                    key=hex(key), status="buf_not_found"))
                continue
            try:
                decoded = run_decode(algo, raw[:length], key)
            except Exception as e:
                decoded = f"<lỗi:{e}>"
            results.append(dict(dest=dest, dest_src=dest_src, length=length,
                                key=hex(key), raw_hex=raw[:length].hex(),
                                decoded=decoded, status="ok"))

    return results, last_key


# === MODULE 2c: GIẢI MÃ ===
def decode_xor(d, k):
    """Giải mã XOR 1 byte: mỗi byte XOR với key."""
    return bytes(b ^ (k & 0xFF) for b in d).decode("latin-1")


def decode_xor_multi(data, key_bytes):
    """Giải mã XOR nhiều byte: data[i] XOR key[i % len(key)]."""
    return bytes(b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(data)).decode("latin-1")


def decode_add(d, k):
    """Giải mã ADD: mỗi byte trừ key."""
    return bytes((b - k) & 0xFF for b in d).decode("latin-1")


def _rol8(b, n):
    """Xoay trái 8-bit."""
    n %= 8
    return ((b << n) | (b >> (8 - n))) & 0xFF


def decode_add_rol(d, k, sh=3):
    """Giải mã ADD+ROL: ROR rồi SUB key."""
    return bytes([(_rol8(b, 8 - (sh % 8)) - k) & 0xFF for b in d]).decode("latin-1")


def run_decode(algo, data, key, **kwargs):
    """Giải mã dữ liệu theo thuật toán được chỉ định."""
    if algo == "xor":
        return decode_xor(data, key)
    if algo == "xor_multi":
        return decode_xor_multi(data, key)  # key là bytes (mảng khoá)
    if algo == "add":
        return decode_add(data, key)
    if algo == "add_rol":
        shift = kwargs.get("shift", 3)
        return decode_add_rol(data, key, shift)
    return decode_xor(data, key)


# === MODULE 2d: ÁNH XẠ ĐIỂM GỌI THEO BẰNG CHỨNG ===
def _map_goi_theo_dich(hf_caller, entry_ham_giai_ma):
    """
    Ánh xạ từng điểm gọi → tên biến đích (đối số đầu tiên), dựa trên High Pcode.
    Trả về dict: {offset_địa_chỉ: tên_biến_đích}.
    """
    from ghidra.program.model.pcode import PcodeOp
    anh_xa = {}
    it = hf_caller.getPcodeOps()
    while it.hasNext():
        op = it.next()
        if op.getOpcode() != PcodeOp.CALL:
            continue
        vn_ham = op.getInput(0)
        if vn_ham is None or vn_ham.getAddress() != entry_ham_giai_ma:
            continue
        dia_chi = op.getSeqnum().getTarget().getOffset()
        if op.getNumInputs() > 1:
            vn_dich = op.getInput(1)
            if vn_dich is not None:
                hv = vn_dich.getHigh()
                if hv is not None:
                    anh_xa[dia_chi] = hv.getName()
    return anh_xa


# === MODULE 2e: GHI COMMENT + BOOKMARK ===
def _comment(program, off, text):
    """Ghi EOL comment vào địa chỉ trong chương trình."""
    from ghidra.program.model.listing import CodeUnit
    addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(off)
    cu = program.getListing().getCodeUnitAt(addr)
    if cu:
        cu.setComment(CodeUnit.EOL_COMMENT, text)


def _bookmark(program, off, label):
    """Thêm bookmark phân tích vào địa chỉ."""
    addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(off)
    program.getBookmarkManager().setBookmark(addr, "Analysis", "DeobfStr", label)


# === PIPELINE CHÍNH ===
def process_binary(binary_path, project_dir=None):
    """Phân tích binary: tìm hàm giải mã, trích xuất và giải mã chuỗi."""
    import pyghidra
    from ghidra.app.decompiler import DecompInterface
    from ghidra.util.task import ConsoleTaskMonitor
    kwargs = {"project_location": project_dir} if project_dir else {}
    with pyghidra.open_program(binary_path, **kwargs) as flat_api:
        program = flat_api.getCurrentProgram()
        monitor = ConsoleTaskMonitor()
        dc = DecompInterface(); dc.openProgram(program)
        print(f"[*] Binary   : {binary_path}", file=sys.stderr)
        print(f"    Kiến trúc: {program.getLanguage().getProcessor()}", file=sys.stderr)
        print(f"    Số hàm   : {program.getFunctionManager().getFunctionCount()}", file=sys.stderr)
        candidates = find_candidates(program, dc, monitor)
        if not candidates:
            print("[-] Không tìm thấy hàm giải mã.", file=sys.stderr)
            dc.dispose()
            return dict(binary=binary_path, results=[])
        print(f"[+] {len(candidates)} ứng viên:", file=sys.stderr)
        for c in candidates:
            print(f"    * {c['name']} @ {c['entry_offset']} [{c['algorithm']}]", file=sys.stderr)
        all_results = []
        for cand in candidates:
            dfunc = cand["func_obj"]; algo = cand["algorithm"]
            calls_by_caller = get_calls_by_caller(program, dfunc.getEntryPoint())
            total = sum(len(v) for v in calls_by_caller.values())
            print(f"\n[*] {dfunc.getName()} có {total} điểm gọi", file=sys.stderr)
            for caller_func, sites in calls_by_caller.items():
                sites_sorted = sorted(sites, key=lambda a: a.getOffset())
                dr = dc.decompileFunction(caller_func, 30, monitor)
                if not dr or not dr.decompileCompleted():
                    continue
                hf_caller = dr.getHighFunction()
                dfn = dr.getDecompiledFunction()
                c_code = dfn.getC() if dfn else ""
                print(f"  Caller: {caller_func.getName()} ({len(sites)} gọi)", file=sys.stderr)
                decoded_list, _ = extract_strings_from_c(c_code, dfunc.getName(), algo)

                # Ánh xạ điểm gọi → biến đích bằng High Pcode
                anh_xa_dich = {}
                if hf_caller is not None:
                    anh_xa_dich = _map_goi_theo_dich(hf_caller, dfunc.getEntryPoint())

                # Xây dict kết quả giải mã, khoá theo tên biến đích
                tu_dien_giai_ma = {}
                co_trung = set()
                for item in decoded_list:
                    for khoa in set(filter(None, [
                        _nws(item.get("dest_src", "")),
                        _nws(item.get("dest", "")),
                        _nws(_lam_sach_bieu_thuc(item.get("dest", ""))),
                    ])):
                        if khoa in tu_dien_giai_ma and tu_dien_giai_ma[khoa] is not item:
                            co_trung.add(khoa)
                        tu_dien_giai_ma[khoa] = item

                for call_addr in sites_sorted:
                    off = call_addr.getOffset()
                    print(f"    call @ 0x{off:x}", file=sys.stderr)
                    ten_dich = anh_xa_dich.get(off)
                    da_ghep = False
                    if ten_dich is not None:
                        # Thử khớp tên biến từ Pcode với kết quả giải mã
                        for khoa_thu in [_nws(ten_dich), _nws(_lam_sach_bieu_thuc(ten_dich))]:
                            if khoa_thu in tu_dien_giai_ma and khoa_thu not in co_trung:
                                info = dict(tu_dien_giai_ma[khoa_thu])
                                info["call_addr"] = f"0x{off:x}"
                                all_results.append(info)
                                da_ghep = True
                                if info.get("status") != "ok":
                                    print(f"      [!] {info['status']}", file=sys.stderr)
                                else:
                                    decoded = info["decoded"]
                                    print(f'      [+] "{decoded}"', file=sys.stderr)
                                    tx = program.startTransaction("deobf")
                                    try:
                                        _comment(program, off, f'deobf [{algo}]: "{decoded}"')
                                        _bookmark(program, off, f"deobf: {decoded}")
                                    finally:
                                        program.endTransaction(tx, True)
                                break
                    if not da_ghep:
                        print(f"      [!] không ghép được điểm gọi với chuỗi", file=sys.stderr)
                        all_results.append(dict(call_addr=f"0x{off:x}", status="khong_ghep_duoc"))

        dc.dispose()
        return dict(binary=binary_path, results=all_results)


def main():
    parser = argparse.ArgumentParser(description="Ghidra Auto Deobfuscation XOR/ADD/ROL")
    parser.add_argument("binary")
    parser.add_argument("--project-dir", default=None)
    parser.add_argument("--json-out", default=None)
    args = parser.parse_args()
    import pyghidra; pyghidra.start()
    output = process_binary(args.binary, args.project_dir)
    js = json.dumps(output, indent=2, ensure_ascii=False)
    if args.json_out:
        open(args.json_out, "w", encoding="utf-8").write(js)
        print(f"[+] Lưu -> {args.json_out}", file=sys.stderr)
    else:
        print(js)
    ok = sum(1 for r in output["results"] if r.get("status") == "ok")
    print(f"\n[=] Hoàn thành: {ok}/{len(output['results'])} chuỗi giải mã thành công.", file=sys.stderr)


if __name__ == "__main__":
    main()
