#!/usr/bin/env python3
# 同进程解析：父进程算 so 基址；fork 子进程解码（instrumented，可能 abort）；父进程解析 caller
import ctypes, glob, os, re, subprocess, sys, bisect

LIB = glob.glob('/usr/local/lib/python3.12/dist-packages/pillow.libs/libopenjp2-*.so.2.5.4')[0]
h = ctypes.CDLL(LIB)


def read_syms(path):
    out = subprocess.run(['readelf', '-sW', path], capture_output=True, text=True).stdout
    s = []
    for ln in out.splitlines():
        p = ln.split()
        if len(p) >= 8 and re.fullmatch(r'[0-9a-fA-F]+', p[1]):
            s.append((int(p[1], 16), p[7]))
    s.sort()
    return s


syms = read_syms(LIB)
addrs = [a for a, _ in syms]
ra = ctypes.cast(h.opj_malloc, ctypes.c_void_p).value
fo = dict((n, v) for v, n in syms)['opj_malloc']
base = ra - fo
print("so base = %#x  (opj_malloc runtime=%#x - fileoff=%#x)" % (base, ra, fo))


def name_of(rt):
    off = rt - base
    i = bisect.bisect_right(addrs, off) - 1
    if i >= 0:
        return "%s+%#x" % (syms[i][1], off - syms[i][0])
    return "?so+%#x" % off


TARGET = sys.argv[1] if len(sys.argv) > 1 else '/tmp/GR23.j2k'
LOG = '/tmp/same_proc.log'
pid = os.fork()
if pid == 0:
    # 子进程：解码（stderr -> 文件），可能 abort
    fd = os.open(LOG, os.O_WRONLY | os.O_CREAT | os.O_TRUNC)
    os.dup2(fd, 2)
    try:
        from PIL import Image
        im = Image.open(TARGET)
        im.load()
        os.write(1, b"CHILD_OK\n")
    except BaseException as e:
        os.write(1, ("CHILD_ERR %r\n" % (e,)).encode())
    os._exit(0)
else:
    os.waitpid(pid, 0)
    log = open(LOG, errors='ignore').read()
    print("子进程日志行数 =", len(log.splitlines()))
    seen = set()
    print("\n=== 每个 (尺寸, caller) 的归属 ===")
    for ln in log.splitlines():
        m = re.search(r'(?:size=(\d+)|n=(\d+) s=(\d+)) -> (0x[0-9a-f]+)(?: \(caller=(0x[0-9a-f]+)\))?', ln)
        if not m:
            continue
        size = int(m.group(1)) if m.group(1) else int(m.group(2)) * int(m.group(3))
        cm = m.group(5)
        if not cm:
            continue
        key = (size, cm)
        if key in seen:
            continue
        seen.add(key)
        print("  size=%-8d addr=%-12s caller=%s -> %s" % (size, m.group(4), cm, name_of(int(cm, 16))))