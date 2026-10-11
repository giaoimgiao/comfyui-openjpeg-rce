#!/usr/bin/env bash
# J2K-PWN 一键复现
D=$(cd "$(dirname "$0")" && pwd)
PD=/usr/local/lib/python3.12/dist-packages/pillow.libs/libopenjp2-0ec72a70.so.2.5.4
[ -f "${PD}.orig" ] && cp "${PD}.orig" "$PD"
timeout 600 python3 -u "$D/exp.py"
