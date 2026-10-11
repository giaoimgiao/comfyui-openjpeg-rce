#!/usr/bin/env python3
# 稳健版：readelf -sW 解析符号 + dlsym 反推 so 基址 -> 把日志 caller 解析成函数名
import ctypes, re, subprocess, bisect, sys, glob

LIB = glob.glob('/usr/local/lib/python3.12/dist-packages/pillow.libs/libopenjp2-*.so.2.5.4')[0]
h = ctypes.CDLL(LIB)


def runtime_addr(name):
    try:
        return ctypes.cast(getattr(h, name), ctypes.c_void_p).value
    except Exception:
        return None


def read_syms(path):
    out = subprocess.run(['readelf', '-sW', path], capture_output=True, text=True).stdout
    syms = []
    for ln in out.splitlines():
        p = ln.split()
        # Num: Value Size Type Bind Vis Ndx Name
        if len(p) >= 8 and re.fullmatch(r'[0-9a-fA-F]+', p[1]):
            try:
                v = int(p[1], 16)
            except ValueError:
                continue
            syms.append((v, p[7]))
    syms.sort()
    return syms


syms = read_syms(LIB)
if not syms:
    print("readelf 解析失败"); sys.exit(1)
print("符号数 =", len(syms))
addrs = [a for a, _ in syms]

base = None
for cand in ('opj_malloc', 'opj_calloc', 'opj_free', 'opj_realloc'):
    ra = runtime_addr(cand)
    if ra is None:
        continue
    for v, n in syms:
        if n == cand:
            base = ra - v
            print("so base = %#x  (由 %s: runtime=%#x - fileoff=%#x)" % (base, cand, ra, v))
            break
    if base:
        break
if base is None:
    print("无法确定 base"); sys.exit(1)


def name_of(rt):
    off = rt - base
    i = bisect.bisect_right(addrs, off) - 1
    if i >= 0:
        return "%s+%#x  (so+%#x)" % (syms[i][1], off - syms[i][0], off)
    return "? so+%#x" % off


log = open(sys.argv[1] if len(sys.argv) > 1 else '/tmp/dm2.out', errors='ignore').read()
callers = sorted(set(re.findall(r'caller=(0x[0-9a-f]+)', log)))
print("\n=== 日志中的 caller 归属 ===")
for c in callers:
    print("  %s -> %s" % (c, name_of(int(c, 16))))

print("\n=== 按分配尺寸标注归属 ===")
seen = set()
for ln in log.splitlines():
    m = re.search(r'(size=(\d+)|n=(\d+) s=(\d+)) -> (0x[0-9a-f]+)', ln)
    if not m:
        continue
    size = int(m.group(2)) if m.group(2) else int(m.group(3)) * int(m.group(4))
    cm = re.search(r'caller=(0x[0-9a-f]+)', ln)
    if not cm:
        continue
    key = (size, cm.group(1))
    if key in seen:
        continue
    seen.add(key)
    if size >= 200:
        print("  size=%-7d addr=%s caller=%s -> %s" % (size, m.group(5), cm.group(1), name_of(int(cm.group(1), 16))))