"""Recover a UE IoStore global AES-256 key from a running game's memory.

Anchor strategy: each mounted IoStore reader keeps its ContainerId next to the
container's AES key. Find known ContainerIds (u64, 8-aligned) in memory, harvest
high-entropy 32-byte windows around each hit, rank by frequency (the one global
key repeats once per mounted container), and validate candidates by AES-256-ECB
decrypting a .utoc directory index.

Needs: root ADB to the device/emulator, numpy, pycryptodome.

  python scan_mem_key.py --pid 1769 --utoc path/to/any_encrypted.utoc \
      --ids-from path/to/utoc_dir [--adb adb] [--serial 127.0.0.1:21503]

The game must be past startup (key registered) — open a car/level first.
"""
import argparse
import glob
import os
import struct
import subprocess
import sys
from collections import Counter

import numpy as np
from Crypto.Cipher import AES

PAGE = 4096
CHUNK = 64 << 20          # read big regions in 64 MB slices
OVERLAP = 2 * PAGE        # keep anchors near slice edges inside a window
WIN = 2048                # bytes searched on each side of an anchor
METHOD_NAMES = (b"Oodle", b"Zlib", b"Gzip", b"LZ4")


def container_ids(folder):
    ids = []
    for p in glob.glob(os.path.join(folder, "**", "*.utoc"), recursive=True):
        with open(p, "rb") as f:
            h = f.read(0x40)
        if len(h) >= 0x40:
            ids.append(struct.unpack_from("<Q", h, 0x38)[0])
    return np.array(sorted(set(ids)), dtype=np.uint64)


def dir_index(utoc):
    """Locate the encrypted directory index by anchoring on the method-name block.

    Summing section sizes drifts with vendor padding, so find the compression
    method name text and take the block that follows it.
    """
    d = open(utoc, "rb").read()
    count, name_len, dir_size = (struct.unpack_from("<I", d, o)[0] for o in (36, 40, 48))
    for name in METHOD_NAMES:
        i = d.find(name, 144)
        if i >= 0:
            start = i + count * name_len
            return d[start:start + dir_size]
    sys.exit("no compression method name found; pass --dir-off manually")


def plausible(pt):
    """Directory index begins with an FString mount point (may be empty: len 1)."""
    n = int.from_bytes(pt[:4], "little", signed=True)
    if not 1 <= n <= 512:
        return False
    if n == 1:
        return pt[4] == 0
    body = pt[4:4 + min(n, 12)]
    return all(32 <= c < 127 or c == 0 for c in body)


def _exec_out(a, shell_cmd):
    """Run a shell command on device via adb exec-out (binary-safe), optionally su."""
    inner = f"su -c '{shell_cmd}'" if a.su else shell_cmd
    cmd = [a.adb] + (["-s", a.serial] if a.serial else []) + ["exec-out", inner]
    return subprocess.run(cmd, capture_output=True, timeout=180).stdout


def read_mem(a, pid, addr, size):
    dd = f"dd if=/proc/{pid}/mem bs={PAGE} skip={addr // PAGE} count={size // PAGE} 2>/dev/null"
    try:
        return _exec_out(a, dd)
    except subprocess.TimeoutExpired:
        return b""


def regions(a):
    cmd = [a.adb] + (["-s", a.serial] if a.serial else []) + ["exec-out", f"cat /proc/{a.pid}/maps"]
    out = []
    for line in subprocess.run(cmd, capture_output=True).stdout.decode(errors="ignore").splitlines():
        p = line.split()
        if len(p) < 2 or "-" not in p[0] or not p[1].startswith("rw"):
            continue
        name = " ".join(p[5:]) if len(p) > 5 else ""
        if name and a.lib not in name and "anon:" not in name:
            continue        # skip dalvik / gralloc / stack / device mappings
        s, e = (int(x, 16) for x in p[0].split("-"))
        out.append((s, e))
    return out


def high_entropy(w):
    return len(set(w)) >= 24 and w.count(0) <= 3


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pid", type=int, required=True)
    ap.add_argument("--utoc", required=True, help="an encrypted .utoc used to validate")
    ap.add_argument("--ids-from", required=True, help="folder of .utoc files for ContainerId anchors")
    ap.add_argument("--adb", default="adb")
    ap.add_argument("--serial", default="")
    ap.add_argument("--lib", default="libUE4", help="engine library name kept in maps filter")
    ap.add_argument("--su", action="store_true", help="wrap dd in su -c (non-root adbd)")
    a = ap.parse_args()

    ct = dir_index(a.utoc)
    ids = container_ids(a.ids_from)
    regs = regions(a)
    total = sum(e - s for s, e in regs)
    print(f"regions={len(regs)} total={total >> 20}MB anchors={len(ids)} dir_index={len(ct)}B")

    freq, anchors, done = Counter(), 0, 0
    for s, e in regs:
        pos = s
        while pos < e:
            data = read_mem(a, a.pid, pos, min(CHUNK + OVERLAP, e - pos))
            done += min(CHUNK, e - pos)
            n8 = len(data) // 8 * 8
            if n8:
                arr = np.frombuffer(data[:n8], dtype=np.uint64)
                for h in np.nonzero(np.isin(arr, ids))[0]:
                    off = int(h) * 8
                    anchors += 1
                    lo, hi = max(0, off - WIN), min(len(data) - 32, off + WIN)
                    for i in range(lo - lo % 4, hi, 4):
                        w = data[i:i + 32]
                        if len(w) == 32 and high_entropy(w):
                            freq[w] += 1
            pos += CHUNK
        sys.stdout.write(f"\r{done >> 20}/{total >> 20}MB anchors={anchors} cands={len(freq)}  ")
        sys.stdout.flush()

    print(f"\nscan done anchors={anchors} candidates={len(freq)}")
    for key, cnt in freq.most_common(200):
        pt = AES.new(key, AES.MODE_ECB).decrypt(ct)
        if plausible(pt):
            print(f"KEY FOUND (seen {cnt}x): 0x{key.hex().upper()}")
            print("decrypted dir-index head:", pt[:64])
            return
    print("no candidate passed validation; top by frequency (inspect manually — the")
    print("validator may be too strict, decrypt the dir index and eyeball the structure):")
    for key, cnt in freq.most_common(10):
        print(f"  {cnt:6d}  {key.hex()}")


if __name__ == "__main__":
    main()
