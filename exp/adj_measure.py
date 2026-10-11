#!/usr/bin/env python3
# 量：同档 bytes(519) 连续两次分配，什么时候才相邻？
import ctypes, gc

R = lambda a: ctypes.c_uint64.from_address(a).value
C = lambda a: R(a - 8) & ~0xf


def show(tag, n=8):
    prevD = None
    for i in range(n):
        D = bytes(519)
        B = bytes(519)
        d = id(B) - id(D)
        delta = ('%#x' % (id(D) - prevD)) if prevD else '-'
        print("%-4s D=%#x(ck %#x) B=%#x(ck %#x)  B-D=%#x  ΔD=%s"
              % (tag, id(D), C(id(D)), id(B), C(id(B)), d, delta))
        prevD = id(D)


gc.collect()
print("--- 1) 直接连续分配 ---")
show("A")
print()
print("--- 2) 先 held 512 个该档，再分配 ---")
hold1 = [bytes(519) for _ in range(512)]
show("B")
print()
print("--- 3) 再 held 512 个，再分配 ---")
hold2 = [bytes(519) for _ in range(512)]
show("C")
print()
print("--- 4) 释放全部 held（造成大量同档空闲块），再分配 ---")
del hold1, hold2
gc.collect()
show("D", 4)