#!/usr/bin/env python3
import re,sys,json,warnings,argparse
from collections import defaultdict
warnings.filterwarnings("ignore",category=DeprecationWarning)

# === MODULE 1: TIM HAM GIAI MA (Pcode heuristic) ===
def _pcode_flags(hf):
    from ghidra.program.model.pcode import PcodeOp
    f=dict(xor=False,add_sub=False,shift=False,or_=False,byte_store=False,byte_load=False,op_count=0)
    it=hf.getPcodeOps()
    while it.hasNext():
        op=it.next(); f["op_count"]+=1; opc=op.getOpcode()
        if opc==PcodeOp.INT_XOR: f["xor"]=True
        elif opc in(PcodeOp.INT_ADD,PcodeOp.INT_SUB): f["add_sub"]=True
        elif opc in(PcodeOp.INT_LEFT,PcodeOp.INT_RIGHT,PcodeOp.INT_SRIGHT): f["shift"]=True
        elif opc==PcodeOp.INT_OR: f["or_"]=True
        elif opc==PcodeOp.STORE:
            v=op.getInput(2)
            if v and v.getSize()==1: f["byte_store"]=True
        elif opc==PcodeOp.LOAD:
            o=op.getOutput()
            if o and o.getSize()==1: f["byte_load"]=True
    return f

def _guess_algo(f):
    if f["xor"] and not f["shift"]: return "xor"
    if f["shift"] and f["or_"] and f["add_sub"]: return "add_rol"
    if f["shift"] and f["or_"]: return "rol"
    if f["add_sub"] and not f["xor"]: return "add"
    return "unknown"

def analyze_function(func,dc,monitor):
    r=dc.decompileFunction(func,30,monitor)
    if not r or not r.decompileCompleted(): return None
    hf=r.getHighFunction()
    if not hf: return None
    df=r.getDecompiledFunction()
    if not df: return None
    c=df.getC() or ""
    if not any(k in c for k in("while","for (","do {")): return None
    f=_pcode_flags(hf)
    if f["op_count"]>200: return None
    if not(f["byte_store"] and f["byte_load"]): return None
    if not f["xor"] and not(f["shift"] and f["or_"]): return None
    return dict(func_obj=func,name=func.getName(),entry=func.getEntryPoint(),
                entry_offset="0x{:x}".format(func.getEntryPoint().getOffset()),
                algorithm=_guess_algo(f),pcode_ops=f["op_count"])

def find_candidates(program,dc,monitor):
    res=[]
    for func in program.getFunctionManager().getFunctions(True):
        if func.isThunk() or func.isExternal(): continue
        info=analyze_function(func,dc,monitor)
        if info: res.append(info)
    return res

# === MODULE 2a: NHOM DIEM GOI THEO CALLER ===
def get_calls_by_caller(program,entry):
    res=defaultdict(list)
    for ref in program.getReferenceManager().getReferencesTo(entry):
        if not ref.getReferenceType().isCall(): continue
        addr=ref.getFromAddress()
        caller=program.getFunctionManager().getFunctionContaining(addr)
        if caller: res[caller].append(addr)
    return res

# === MODULE 2b: PARSE C DECOMPILED ===
def _parse_c_str(s):
    out=bytearray(); i=0
    while i<len(s):
        if s[i]!="\\": out.append(ord(s[i])); i+=1; continue
        i+=1
        if i>=len(s): break
        c=s[i]
        if c=="x" and i+2<len(s):
            try: out.append(int(s[i+1:i+3],16)); i+=3
            except: out.append(ord("x")); i+=1
        elif c=="n": out.append(10); i+=1
        elif c=="t": out.append(9);  i+=1
        elif c=="r": out.append(13); i+=1
        elif c=="0": out.append(0);  i+=1
        elif c=="\\": out.append(92); i+=1
        elif c=='"': out.append(34); i+=1
        else: out.append(ord(c)); i+=1
    return bytes(out)

def _nws(e): return re.sub(r"\s+","",e)

def extract_strings_from_c(c_code,func_name,algo):
    results=[]; last_key=None
    aliases={}
    for m in re.finditer(r"^\s*(\w+)\s*=\s*([\w\s\+\-x0-9_]+?)\s*;",c_code,re.M):
        aliases[m.group(1).strip()]=m.group(2).strip()
    def resolve(e): e=e.strip(); return aliases.get(e,e)
    buf_map={}
    
    # --- builtin_strncpy ---
    pat_cpy=re.compile(r'builtin_strncpy\s*\(\s*([^,]+?)\s*,\s*"((?:[^"\\]|\\.)*)"',re.S)
    for m in pat_cpy.finditer(c_code):
        dest=_nws(resolve(m.group(1))); raw=_parse_c_str(m.group(2))
        buf_map[dest]=raw
        print(f"  [parse] strncpy {dest!r} = {raw.hex()}",file=sys.stderr)
        
    # --- Array element assignments: dest[idx] = val; ---
    array_assignments = defaultdict(dict)
    pat_assign = re.compile(r'^\s*([A-Za-z0-9_]+)\[(\d+)\]\s*=\s*(.+?)\s*;', re.M)
    for m in pat_assign.finditer(c_code):
        base, idx, val_str = _nws(m.group(1)), int(m.group(2)), m.group(3).strip()
        if val_str.startswith("'") and val_str.endswith("'"):
            ch = val_str[1:-1]
            if ch.startswith('\\'):
                if ch == '\\0': val = 0
                elif ch == '\\n': val = 10
                elif ch == '\\t': val = 9
                elif ch == '\\r': val = 13
                elif ch == '\\"': val = 34
                elif ch == '\\\\': val = 92
                else: val = ord(ch[-1])
            else:
                val = ord(ch)
        elif val_str.startswith("0x") or val_str.startswith("-0x"):
            val = int(val_str, 16)
        else:
            try: val = int(val_str)
            except: val = 0
        array_assignments[base][idx] = val & 0xFF
        
    for base, byte_dict in array_assignments.items():
        if not byte_dict: continue
        max_idx = max(byte_dict.keys())
        buf = bytearray(max_idx + 1)
        for idx, val in byte_dict.items(): buf[idx] = val
        buf_map[base] = bytes(buf)
        print(f"  [parse] array {base!r} = {bytes(buf).hex()}", file=sys.stderr)

    # --- Stack model: ghidra "local_XX", "uStack_XX", "acStack_XX"... = vi tri -0xXX. Gom byte tu strncpy + gan so nguyen ---
    def _lam_sach_bieu_thuc(bieu_thuc):
        """Loại bỏ ép kiểu cast (char *), (undefined1 *) và toán tử lấy địa chỉ & trong C decompiled."""
        bt = re.sub(r'\([^)]+\)', '', bieu_thuc)
        return bt.strip().lstrip('&').strip()

    def _stk(ten):
        ten_sach = _lam_sach_bieu_thuc(ten)
        m = re.fullmatch(r"(?:local_|[a-zA-Z]*Stack_|stack_?)([0-9a-fA-F]+)", ten_sach)
        return -int(m.group(1), 16) if m else None

    mem = {}
    for bk, bv in buf_map.items():
        a = _stk(bk)
        if a is not None:
            for j, b in enumerate(bv): mem[a + j] = b

    tsize = {"undefined": 1, "undefined1": 1, "undefined2": 2, "undefined4": 4, "undefined8": 8,
             "byte": 1, "char": 1, "short": 2, "ushort": 2, "int": 4, "uint": 4,
             "long": 8, "ulong": 8, "longlong": 8, "ulonglong": 8}
    vsize = {}
    for m in re.finditer(r"^\s*(?:unsigned\s+)?(\w+)\s+((?:local_|[a-zA-Z]*Stack_|stack_?)[0-9a-fA-F]+)\s*;", c_code, re.M):
        if m.group(1) in tsize: vsize[m.group(2)] = tsize[m.group(1)]

    for m in re.finditer(r"^\s*((?:local_|[a-zA-Z]*Stack_|stack_?)[0-9a-fA-F]+)\s*=\s*(-?0x[0-9a-fA-F]+|\d+)U?L{0,2}\s*;", c_code, re.M):
        a = _stk(m.group(1)); sz = vsize.get(m.group(1))
        if a is None or not sz: continue
        v = int(m.group(2), 0) & ((1 << (8 * sz)) - 1)
        for j, b in enumerate(v.to_bytes(sz, "little")): mem[a + j] = b
        print(f"  [parse] scalar {m.group(1)!r} = {v:0{sz*2}x} ({sz}B)", file=sys.stderr)

    def stack_read(dich, do_dai):
        dich_sach = _lam_sach_bieu_thuc(dich)
        m = re.fullmatch(r"((?:local_|[a-zA-Z]*Stack_|stack_?)[0-9a-fA-F]+)(?:\+(\w+))?", dich_sach)
        if not m: return None
        a = _stk(m.group(1))
        if a is None: return None
        if m.group(2):
            try: a += int(m.group(2), 0)
            except ValueError: return None
        if all(a + j in mem for j in range(do_dai)): return bytes(mem[a + j] for j in range(do_dai))
        return None

    pat_dec = re.compile(r"\b" + re.escape(func_name) + r"\s*\(\s*([^)]+)\)\s*;", re.S)
    for m in pat_dec.finditer(c_code):
        args = [a.strip() for a in m.group(1).split(",")]
        if len(args) < 2: continue
        dest_raw = resolve(args[0])
        dest = _nws(dest_raw)
        dest_clean = _nws(_lam_sach_bieu_thuc(dest_raw))
        try: length = int(args[1], 0)
        except: continue
        if len(args) >= 3:
            try: last_key = int(args[2], 0)
            except ValueError:
                # Tham số key có mặt nhưng không đọc được (vd 'Z', (char)0x5a): không dùng lại khoá cũ.
                last_key = None
                print(f"      [!] khong parse duoc key {args[2]!r}", file=sys.stderr)
        key = last_key
        if key is None:
            results.append(dict(dest=dest, length=length, status="key_unknown")); continue
        
        raw = buf_map.get(dest) or buf_map.get(dest_clean)
        if raw is None:
            # Handle local_13+5
            m_off = re.match(r'^([A-Za-z0-9_]+)\+([x0-9a-fA-F]+)$', dest_clean)
            if m_off:
                base = m_off.group(1)
                try:
                    offset = int(m_off.group(2), 0)
                    if base in buf_map: raw = buf_map[base][offset:]
                except: pass
                
        if raw is None: raw = stack_read(dest, length)

        if raw is None:
            for bk, bv in buf_map.items():
                if dest_clean.startswith(bk) or bk.startswith(dest_clean): raw = bv; break

                
        if raw is None:
            results.append(dict(dest=dest,length=length,key=hex(key),status="buf_not_found")); continue
            
        try: decoded=run_decode(algo,raw[:length],key)
        except Exception as e: decoded=f"<error:{e}>"
        results.append(dict(dest=dest,length=length,key=hex(key),
                            raw_hex=raw[:length].hex(),decoded=decoded,status="ok"))
    return results,last_key

# === MODULE 2c: GIAI MA ===
def decode_xor(d,k): return bytes(b^(k&0xFF) for b in d).decode("latin-1")
def decode_add(d,k): return bytes((b-k)&0xFF for b in d).decode("latin-1")
def _rol8(b,n):
    n%=8; return ((b<<n)|(b>>(8-n)))&0xFF
def decode_add_rol(d,k,sh=3):
    return bytes([(_rol8(b,8-(sh%8))-k)&0xFF for b in d]).decode("latin-1")
def run_decode(algo,data,key):
    if algo=="xor": return decode_xor(data,key)
    if algo=="add": return decode_add(data,key)
    if algo=="add_rol": return decode_add_rol(data,key,3)
    return decode_xor(data,key)

# === MODULE 2d: GHI COMMENT + BOOKMARK ===
def _comment(program,off,text):
    from ghidra.program.model.listing import CodeUnit
    addr=program.getAddressFactory().getDefaultAddressSpace().getAddress(off)
    cu=program.getListing().getCodeUnitAt(addr)
    if cu: cu.setComment(CodeUnit.EOL_COMMENT,text)

def _bookmark(program,off,label):
    addr=program.getAddressFactory().getDefaultAddressSpace().getAddress(off)
    program.getBookmarkManager().setBookmark(addr,"Analysis","DeobfStr",label)

# === PIPELINE CHINH ===
def process_binary(binary_path,project_dir=None):
    import pyghidra
    from ghidra.app.decompiler import DecompInterface
    from ghidra.util.task import ConsoleTaskMonitor
    kwargs={"project_location":project_dir} if project_dir else {}
    with pyghidra.open_program(binary_path,**kwargs) as flat_api:
        program=flat_api.getCurrentProgram()
        monitor=ConsoleTaskMonitor()
        dc=DecompInterface(); dc.openProgram(program)
        print(f"[*] Binary   : {binary_path}",file=sys.stderr)
        print(f"    Kien truc: {program.getLanguage().getProcessor()}",file=sys.stderr)
        print(f"    So ham   : {program.getFunctionManager().getFunctionCount()}",file=sys.stderr)
        candidates=find_candidates(program,dc,monitor)
        if not candidates:
            print("[-] Khong tim thay ham giai ma.",file=sys.stderr)
            dc.dispose(); return dict(binary=binary_path,results=[])
        print(f"[+] {len(candidates)} ung vien:",file=sys.stderr)
        for c in candidates:
            print(f"    * {c['name']} @ {c['entry_offset']} [{c['algorithm']}]",file=sys.stderr)
        all_results=[]
        for cand in candidates:
            dfunc=cand["func_obj"]; algo=cand["algorithm"]
            calls_by_caller=get_calls_by_caller(program,dfunc.getEntryPoint())
            total=sum(len(v) for v in calls_by_caller.values())
            print(f"\n[*] {dfunc.getName()} co {total} diem goi",file=sys.stderr)
            for caller_func,sites in calls_by_caller.items():
                sites_sorted=sorted(sites,key=lambda a:a.getOffset())
                dr=dc.decompileFunction(caller_func,30,monitor)
                if not dr or not dr.decompileCompleted(): continue
                dfn=dr.getDecompiledFunction()
                c_code=dfn.getC() if dfn else ""
                print(f"  Caller: {caller_func.getName()} ({len(sites)} goi)",file=sys.stderr)
                decoded_list,_=extract_strings_from_c(c_code,dfunc.getName(),algo)
                for i,call_addr in enumerate(sites_sorted):
                    off=call_addr.getOffset()
                    print(f"    call @ 0x{off:x}",file=sys.stderr)
                    if i>=len(decoded_list):
                        all_results.append(dict(call_addr=f"0x{off:x}",status="index_out_of_range")); continue
                    info=dict(decoded_list[i]); info["call_addr"]=f"0x{off:x}"
                    all_results.append(info)
                    if info.get("status")!="ok":
                        print(f"      [!] {info['status']}",file=sys.stderr); continue
                    decoded=info["decoded"]
                    print(f'      [+] "{decoded}"',file=sys.stderr)
                    tx=program.startTransaction("deobf")
                    try:
                        _comment(program,off,f'deobf [{algo}]: "{decoded}"')
                        _bookmark(program,off,f"deobf: {decoded}")
                    finally: program.endTransaction(tx,True)
        dc.dispose()
        return dict(binary=binary_path,results=all_results)

def main():
    parser=argparse.ArgumentParser(description="Ghidra Auto Deobfuscation XOR/ADD/ROL")
    parser.add_argument("binary")
    parser.add_argument("--project-dir",default=None)
    parser.add_argument("--json-out",default=None)
    args=parser.parse_args()
    import pyghidra; pyghidra.start()
    output=process_binary(args.binary,args.project_dir)
    js=json.dumps(output,indent=2,ensure_ascii=False)
    if args.json_out: open(args.json_out,"w",encoding="utf-8").write(js); print(f"[+] Luu -> {args.json_out}",file=sys.stderr)
    else: print(js)
    ok=sum(1 for r in output["results"] if r.get("status")=="ok")
    print(f"\n[=] Hoan thanh: {ok}/{len(output['results'])} chuoi giai ma thanh cong.",file=sys.stderr)

if __name__=="__main__": main()
