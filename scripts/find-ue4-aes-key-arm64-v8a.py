# find-ue4-aes-key-arm64-v8a.py
# By GHFear @ IllusorySoftware
# IDA Python: load arm64-v8a libUE4.so, then File > Script file... and run this.
# Finds the pak-encryption-key delegate by signature, follows it to the callback,
# and prints the 32-byte AES key the callback references (only works when the key
# is an embedded constant, not assembled/decrypted at runtime).

import idc
import ida_search
import ida_bytes
import ida_kernwin
import ida_ua
import idautils
import ida_funcs
import binascii

pattern = "? ? ? B0 ? ? ? F9 ? ? ? 94 ? ? ? ? ? ? ? 91 E0 03 14 AA ? ? ? 94 E0 03 14 AA ? ? ? 52 ? ? ? 94"


def find_first_pattern(pat):
    ea = ida_search.find_binary(0, idc.get_inf_attr(idc.INF_MAX_EA), pat, 16, ida_search.SEARCH_DOWN)
    print(f"[DEBUG] Signature found at 0x{ea:016X}" if ea != idc.BADADDR else "[DEBUG] Signature not found")
    return ea


def get_mnemonic(ea):
    try:
        return idc.print_insn_mnem(ea).lower()
    except Exception:
        return None


def compute_symbol_ptr_from_adrp_ldr(adrp_ea):
    adrp_val = idc.get_operand_value(adrp_ea, 1)
    page_base = adrp_val & ~0xFFF
    print(f"[DEBUG] ADRP value: 0x{adrp_val:016X}, page base: 0x{page_base:016X}")
    ldr_ea = adrp_ea + 4
    for i in range(6):
        ea = ldr_ea + 4 * i
        mnem = get_mnemonic(ea)
        if not mnem or not mnem.startswith("ldr"):
            continue
        off = idc.get_operand_value(ea, 1) or idc.get_operand_value(ea, 2)
        if not off:
            insn = ida_ua.insn_t()
            if ida_ua.decode_insn(insn, ea):
                for op in insn.ops:
                    if getattr(op, "type", None) == ida_ua.o_imm:
                        off = getattr(op, "value", None)
                        break
        if off is not None:
            symbol_addr = (page_base & ~0xFFF) + off
            print(f"[DEBUG] LDR at 0x{ea:016X}, offset: 0x{off:X}, symbol ptr: 0x{symbol_addr:016X}")
            return symbol_addr
    return None


def readable_qword(ea):
    if ea == idc.BADADDR or ea is None:
        return None
    maxea = idc.get_inf_attr(idc.INF_MAX_EA)
    if ea < 0 or ea + 8 > maxea:
        return None
    val = ida_bytes.get_qword(ea)
    print(f"[DEBUG] QWORD at 0x{ea:016X} = 0x{val:016X}")
    return val


def find_data_ref_in_callback(func_ea):
    f = ida_funcs.get_func(func_ea)
    if not f:
        return None
    for insn in idautils.FuncItems(f.start_ea):
        m = get_mnemonic(insn)
        if not m:
            continue
        if m in ("adrl", "adr", "adr.w"):
            val = idc.get_operand_value(insn, 1)
            if val:
                print(f"[DEBUG] Found data ref via {m} at 0x{insn:016X}: 0x{val:016X}")
                return val
        if m == "adrp":
            page = idc.get_operand_value(insn, 1)
            next_ea = idc.next_head(insn, f.end_ea)
            if get_mnemonic(next_ea) == "add":
                off = idc.get_operand_value(next_ea, 2)
                addr = (page & ~0xFFF) + off
                print(f"[DEBUG] Found data ref via ADRP+ADD at 0x{insn:016X}+0x{next_ea-insn:X}: 0x{addr:016X}")
                return addr
    return None


ea = find_first_pattern(pattern)
if ea == idc.BADADDR or ea is None:
    raise SystemExit(0)

if get_mnemonic(ea) != "adrp":
    for delta in range(-12, 16, 4):
        if get_mnemonic(ea + delta) == "adrp":
            ea += delta
            print(f"[DEBUG] Adjusted to ADRP at 0x{ea:016X}")
            break

symbol_ptr = compute_symbol_ptr_from_adrp_ldr(ea)
if not symbol_ptr:
    print("[DEBUG] Failed to resolve symbol pointer")
    raise SystemExit(0)

callback_func = readable_qword(symbol_ptr)
if not callback_func:
    print("[DEBUG] Failed to read callback pointer")
    raise SystemExit(0)
print(f"[DEBUG] Callback function at 0x{callback_func:016X}")

data_addr = find_data_ref_in_callback(callback_func)
if not data_addr:
    print("[DEBUG] Failed to locate AES key reference in callback")
    raise SystemExit(0)
print(f"[DEBUG] AES key data address: 0x{data_addr:016X}")

data = ida_bytes.get_bytes(data_addr, 32)
if not data or len(data) < 32:
    print(f"[DEBUG] Failed to read 32 bytes at 0x{data_addr:016X}")
    raise SystemExit(0)

hexstr = binascii.hexlify(data).decode("ascii")
print("AES Key: 0x" + hexstr)

ida_kernwin.jumpto(data_addr)
