#!/usr/bin/env python3
# check_target.py —— 目标环境检测器
#   1) 报告目标 Python 的 Pillow 版本 / vendored openjpeg 路径与版本
#   2) 用 DoS PoC 在【子进程】里跑一次解码，根据进程是否崩溃判断该 OOB 是否存在
#
# 用法：
#   python3 check_target.py
#   python3 check_target.py --python /opt/conda/bin/python --poc ./poc_dos.jp2
import argparse, glob, os, subprocess, sys

CODE_INFO = r'''
import PIL, glob, os, sys
try:
    print("PILLOW_VERSION", PIL.__version__)
except Exception as e:
    print("PILLOW_VERSION", "ERR", e)
try:
    import PIL, os, glob
    d = os.path.dirname(PIL.__file__)
    up = os.path.dirname(d)
    libs = (glob.glob(os.path.join(d, "*.libs", "*openjp2*")) +
            glob.glob(os.path.join(up, "*.libs", "*openjp2*")))
    print("OPENJPEG_LIBS", libs)
except Exception as e:
    print("OPENJPEG_LIBS", "ERR", e)
'''

CODE_PROBE = r'''
import sys
from PIL import Image
p = sys.argv[1]
im = Image.open(p)
im.load()
print("DECODE_OK")
'''


def run_py(py, code, args=()):
    return subprocess.run([py, "-c", code, *args], capture_output=True, text=True, timeout=180)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--python", default=sys.executable, help="目标 python 解释器路径")
    ap.add_argument("--poc", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "poc_dos.jp2"))
    a = ap.parse_args()

    print("== 目标 ==")
    print("python :", a.python)
    r = run_py(a.python, CODE_INFO)
    print(r.stdout.strip() or r.stderr.strip())

    print("\n== DoS PoC 探测 ==")
    print("poc    :", a.poc)
    if not os.path.exists(a.poc):
        print("[!] PoC 不存在")
        return 2
    try:
        r = run_py(a.python, CODE_PROBE, (a.poc,))
    except subprocess.TimeoutExpired:
        print("[?] 超时（可能卡死 —— 也算可疑）")
        return 3
    out = (r.stdout + r.stderr).strip()
    print("rc     :", r.returncode)
    if out:
        print("output :", out[-300:])

    if r.returncode == 0 and "DECODE_OK" in r.stdout:
        print("\n[结论] 未观察到崩溃 —— 该实现可能已修复 / 或版本不符。")
    else:
        print("\n[结论] 解码进程异常退出（rc=%d, 负 rc 表示信号）—— 目标很可能存在该越界写。" % r.returncode)
        print("       注：这里只证明【可达越界写/崩溃】；RCE 需要目标机上的执行点（见 exp/）。")
    return 0


if __name__ == "__main__":
    sys.exit(main())