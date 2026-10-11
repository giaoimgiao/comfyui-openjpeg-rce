#!/usr/bin/env python3
# 参数对齐：正确读骨架参数 -> 按同样参数重编自定义数据 -> 组装 hybrid -> 验证像素
import io, struct, subprocess, sys
from PIL import Image


def header_markers(d):
    """只在 header 区间（第一个 SOD 之前）walk marker"""
    out = []
    i = 0
    n = len(d)
    while i < n - 1:
        if d[i] != 0xFF or d[i + 1] in (0x00, 0xFF):
            i += 1
            continue
        m = d[i + 1]
        if m == 0x4F:
            out.append((i, m, i + 2, i + 2)); i += 2; continue
        if m == 0x93:                      # SOD —— header 到此结束
            out.append((i, m, i + 2, i + 2)); break
        L = struct.unpack('>H', d[i + 2:i + 4])[0]
        out.append((i, m, i + 4, i + 2 + L))
        i += 2 + L
    return out


def parse_params(path):
    d = open(path, 'rb').read()
    hm = header_markers(d)
    soc = [x for x in hm if x[1] == 0x4F]
    cod = [x for x in hm if x[1] == 0x52]
    siz = [x for x in hm if x[1] == 0x51]
    first_sod = next((x[0] for x in hm if x[1] == 0x93), None)
    p = {}
    if siz:
        seg = d[siz[0][2]:siz[0][3]]
        xsiz, ysiz, xosiz, yosiz, xtsiz, ytsiz, xtos, ytos = struct.unpack('>IIIIIIII', seg[2:34])
        ncomp = struct.unpack('>H', seg[34:36])[0]
        p['siz'] = dict(xsiz=xsiz, ysiz=ysiz, ncomp=ncomp, xtsiz=xtsiz, ytsiz=ytsiz)
    if cod:
        seg = d[cod[0][2]:cod[0][3]]
        p['cod'] = dict(Scod=seg[0], prog=seg[1], layers=struct.unpack('>H', seg[2:4])[0],
                        mct=seg[4], numres=seg[5], cbw=seg[6], cbh=seg[7],
                        cblksty=seg[8], qmfbid=seg[9],
                        precincts=list(seg[10:]) if len(seg) > 10 else [])
    # tile-part 边界（用 SOT 搜索 + SOD 跳跃）
    sots = []
    i = first_sod + 2 if first_sod else 0
    while True:
        j = d.find(b'\xff\x90', i)
        if j < 0:
            break
        sots.append(j)
        k = d.find(b'\xff\x93', j)
        if k < 0:
            break
        i = k + 2
    eoc = d.rfind(b'\xff\xd9')
    p['header'] = d[:sots[0]] if sots else d[:eoc]
    p['TPs'] = []
    for idx, s in enumerate(sots):
        end = sots[idx + 1] if idx + 1 < len(sots) else eoc
        p['TPs'].append(bytearray(d[s:end]))
    p['eoc'] = eoc
    p['data'] = d
    return p


def fix_psot(tp):
    if len(tp) >= 12 and tp[0] == 0xFF and tp[1] == 0x90:
        tp[6:10] = struct.pack('>I', len(tp))
    return tp


if __name__ == "__main__":
    sk = parse_params('/tmp/exp/base.j2k')
    print("[骨架] SIZ:", sk['siz'])
    print("[骨架] COD:", sk['cod'])
    print("[骨架] tiles=%d  header=%d" % (len(sk['TPs']), len(sk['header'])))

    nr = sk['cod']['numres']
    prec = sk['cod']['precincts']
    print("[*] 用骨架参数重编数据: num_resolutions=%d precinct=%s" % (nr, prec))

    # 重编：16x16 L 图，tile 8x8，首像素 = 0x9c
    kw = dict(tile_size=(8, 8), num_resolutions=nr)
    if prec:
        kw['precinct_size'] = tuple(prec)
    code = ("from PIL import Image\n"
            "im = Image.new('L', (16,16))\n"
            "im.putdata([0x9c] + [0]*255)\n"
            "im.save('/tmp/d2.j2k','JPEG2000', **%r)\n" % (kw,))
    r = subprocess.run([sys.executable, '-c', code], capture_output=True, text=True)
    print("[*] 重编 rc=%d %s" % (r.returncode, (r.stderr or '')[:80]))
    if r.returncode != 0:
        sys.exit(1)

    dt = parse_params('/tmp/d2.j2k')
    print("[数据] COD:", dt['cod'])
    print("[数据] tiles=%d" % len(dt['TPs']))

    # 组装 hybrid
    blob = bytearray(sk['header'])
    for tp in dt['TPs']:
        blob += fix_psot(bytearray(tp))
    blob += sk['data'][sk['eoc']:sk['eoc'] + 2]
    open('/tmp/hybrid2.j2k', 'wb').write(bytes(blob))
    print("[*] hybrid = %d 字节" % len(blob))

    im = Image.open(io.BytesIO(bytes(blob))); im.load()
    px = list(im.getdata())
    print("[*] hybrid 解码: %s %s" % (im.size, im.mode))
    print("    前 4 像素:", [hex(v) for v in px[:4]], " 期望 [0x9c, 0, 0, 0]")
    print("[*] 像素正确 =", px[0] == 0x9c)