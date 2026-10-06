#!/usr/bin/env python3
"""
debug_pcode.py -- In Pcode tai cac diem goi ham giai ma de debug

Cach dung:
  source env.sh
  python3 debug_pcode.py test_bins/bin/xor_simple_O2_sym 0x1011e0

Tham so 2 (0x1011e0) la dia chi ham giai ma lay tu ket qua find_candidates.py
"""
import sys
import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)


def dump_varnode(vn, label=""):
    """In thong tin cua 1 varnode."""
    if vn is None:
        print(f"      {label}: None")
        return
    space = vn.getAddress().getAddressSpace().getName() if not vn.isConstant() and not vn.isUnique() and not vn.isRegister() else "?"
    print(f"      {label}: const={vn.isConstant()} unique={vn.isUnique()} "
          f"register={vn.isRegister()} size={vn.getSize()} offset=0x{vn.getOffset():x}")
    def_op = vn.getDef()
    if def_op:
        print(f"        -> defined by: {def_op.getMnemonic()} (opcode={def_op.getOpcode()})")


def dump_call_site(program, decompiler, monitor, call_addr, target_addr):
    from ghidra.program.model.pcode import PcodeOp
    off = call_addr.getOffset()
    print(f"\n{'='*60}")
    print(f"Call site @ 0x{off:x}")

    func = program.getFunctionManager().getFunctionContaining(call_addr)
    if not func:
        print("  [!] Khong tim thay ham chua call site nay")
        return

    result = decompiler.decompileFunction(func, 30, monitor)
    if not result or not result.decompileCompleted():
        print("  [!] Decompile that bai")
        return

    high_func = result.getHighFunction()
    it = high_func.getPcodeOps()
    while it.hasNext():
        op = it.next()
        if op.getOpcode() != PcodeOp.CALL:
            continue
        if op.getSeqnum().getTarget() != call_addr:
            continue

        print(f"  Tim thay CALL op tai seqnum {op.getSeqnum().getTarget()}")
        print(f"  So dau vao: {op.getNumInputs()}")

        # input[0] la callee
        callee_vn = op.getInput(0)
        print(f"\n  [input 0 - callee]:")
        dump_varnode(callee_vn, "callee")

        # in cac tham so thuc su
        for i in range(1, op.getNumInputs()):
            vn = op.getInput(i)
            print(f"\n  [input {i} - param {i}]:")
            dump_varnode(vn, f"param{i}")

            # Neu co define op, in them thong tin
            if vn is not None and vn.getDef() is not None:
                def_op = vn.getDef()
                print(f"    Define op mnemonic: {def_op.getMnemonic()}")
                for j in range(def_op.getNumInputs()):
                    sub_vn = def_op.getInput(j)
                    dump_varnode(sub_vn, f"  input[{j}]")

        # In them: tat ca STORE truoc diem goi nay (de tim byte init cua buffer)
        print(f"\n  --- STORE ops gan diem goi (3 lenh cuoi trong PcodeOps) ---")
        break

    # In Pcode C decompiled de xem context
    decomp_func = result.getDecompiledFunction()
    if decomp_func:
        c_code = decomp_func.getC() or ""
        # Chi in 20 dong xung quanh
        lines = c_code.split('\n')
        print(f"\n  --- C Decompiled ({len(lines)} dong) ---")
        for ln in lines:
            print(f"    {ln}")


def main():
    if len(sys.argv) < 3:
        print("Cach dung: python3 debug_pcode.py <binary> <decode_func_addr_hex>")
        print("  Vi du:   python3 debug_pcode.py test_bins/bin/xor_simple_O2_sym 0x1011e0")
        sys.exit(1)

    binary    = sys.argv[1]
    func_addr = int(sys.argv[2], 16)

    import pyghidra
    pyghidra.start()

    from ghidra.app.decompiler import DecompInterface
    from ghidra.util.task import ConsoleTaskMonitor

    with pyghidra.open_program(binary) as flat_api:
        program    = flat_api.getCurrentProgram()
        monitor    = ConsoleTaskMonitor()
        decompiler = DecompInterface()
        decompiler.openProgram(program)

        # Tim dia chi ham giai ma
        addr_space = program.getAddressFactory().getDefaultAddressSpace()
        target_ghidra_addr = addr_space.getAddress(func_addr)

        # Lay cac XREF
        call_sites = []
        for ref in program.getReferenceManager().getReferencesTo(target_ghidra_addr):
            if ref.getReferenceType().isCall():
                call_sites.append(ref.getFromAddress())

        print(f"Tim thay {len(call_sites)} diem goi den 0x{func_addr:x}")
        for call_addr in call_sites:
            dump_call_site(program, decompiler, monitor, call_addr, target_ghidra_addr)

        decompiler.dispose()


if __name__ == "__main__":
    main()
