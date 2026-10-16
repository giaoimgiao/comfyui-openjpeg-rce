# 两个仓库的关系与差异（互相引用）

本仓库 **[comfyui-openjpeg-rce](https://github.com/giaoimgiao/comfyui-openjpeg-rce)** 与
**[openjpeg-j2k-oob-to-arb-rw](https://github.com/giaoimgiao/openjpeg-j2k-oob-to-arb-rw)**
研究的是**同一个漏洞**（Pillow 12.3.0 vendored openjpeg 2.5.4，`opj_j2k_read_sod()` 越界写）
与**同一个写入原语**（6 个 qword；写出去的值 = 文件内偏移）。
**区别只在最后一段：怎么把原语变成"执行"。**

---

## 一、对照表

| 维度 | **A**：[openjpeg-j2k-oob-to-arb-rw](https://github.com/giaoimgiao/openjpeg-j2k-oob-to-arb-rw) | **B**：comfyui-openjpeg-rce（本仓库） |
|---|---|---|
| 根因 | `read_sod()`：按 TLM 条目数分配、按 SOT 的 `TPsot` 写入 | 同一个 |
| 写入原语 | 6 个 qword（值 = 文件内偏移，受文件大小约束） | 同一个 |
| 堆编排思想 | 排空同档 + 成对 `[gap][victim]` + 只释放对齐的 gap | 同一个（victim 换成大元组） |
| **被害对象** | `bytes(608)` | **元组（110 项 = 904 B）** |
| **图片改写哪些字段** | `ob_type(+0x08)`、`view.buf(+0x38)` ⇒ **类型混淆成 memoryview** | `ob_type(+0x08)`、**`item2(+0x28)` ⇒ 指针劫持到攻击者缓冲区** |
| **中间能力** | **任意读写 + 信息泄露（ASLR 归零）** | 不需要中间能力，一次到位 |
| **需要几次解码** | **2 次**（①把命令写进 `str` 首字节 ②把 `system` 写入 `PyUnicode_Type.tp_repr`） | **1 次** |
| **执行点来源** | 改写**解释器全局类型对象**的槽（`tp_repr`） | **攻击者缓冲区里的假 `PyTypeObject`**，其 `tp_repr = system@plt` |
| 触发动作 | `repr(str)` | `repr(元组[2])` |
| 主要难点 | **memoryview 元数据**：`format/shape/strides/itemsize` 三大约束 | **不需要任何元数据**（这是 B 最大简化） |
| 附带能力 | ✅ 通用原语（任意读写、泄露） | ❌ 不含任意读写 |

---

## 二、两者是"组合拳"，不是替代

- **A 提供原语与泄露**：一旦把 victim 变成 memoryview，`mv[i]` / `mv[i]=x` 就是任意读写；
  这是**远程目标上"拿地址"的唯一手段**（B 需要预先知道攻击者缓冲区的地址）。
- **B 提供更短的执行链**：不需要构造合法 memoryview 元数据、只需一次解码；
  把执行点放在**自己的缓冲区**里，不去改动解释器的全局类型表。
- **组合方式**：远程目标上先用 A 泄露地址 ⇒ 再用 B 的路线开火。

---

## 三、B 记下、A 里没有的实测结论

1. **分配器边界**：CPython 小对象池 pymalloc 只吃 **≤512 字节**；
   想与 `tp_index`（glibc malloc）相邻，victim **必须 >512 B**
   （`tuple(5)`=64B ✗ 永远不相邻；`bytes(519)`=552B ✓；`tuple(110)`=904B ✓）。
2. **6 个槽的精确映射**（实测，不是推测）：
   ```
   victim-0x10 : A-2      victim-0x08 : A      victim+0x08 : A+12  ← ob_type
   victim+0x10 : B+4      victim+0x20 : B+16   victim+0x28 : C+4   ← item2
   ```
   每对写出的值是 `(上一个值+12, 当前值)` 的形式（源自 builder 的 `-14 / -10 / +12` 常数），
   **必须按实测反推 A/B/C，不能按直觉**。
3. **chunk 头伪装**：写窗口会顺手改到 `size` / `prev_size`
   ⇒ 写进去的值要挑得让 glibc 不 `abort`。
4. **`gc.disable()`**：不关 GC，GC 会遍历被改坏的元素而崩溃。
5. **触发槽的选择**：`tp_repr` 比 `tp_dealloc` 更容易被服务器**自然触发**
   （日志打印、`str()`、f-string、错误回显都走它）。

---

## 四、共同的边界（两个仓库都一样）

| 场景 | 结果 |
|---|---|
| 非 PIE 的 CPython（实测 `Type: EXEC`，基址 `0x400000`） | ✅ 完整 RCE |
| PIE + ASLR 的 CPython | ❌ 值域受文件大小限制 ⇒ 类型对象地址（`0x7f…`）**不可表达** ⇒ 只能 DoS |
| 上传限制 < ~11 MB | ❌ 值域不足 |
| 服务器解码后完全不碰被害元素 | ⚠️ 需要一次"服务器行为映射"（打印/日志/序列化路径） |

移植到 x86-64 目标需重算：`PyTuple_Type`（或目标 victim 类型）地址、`system@plt` 地址、目标是否非 PIE。

---

## 五、文档交叉引用

- **A**（原语 / 任意读写 / 泄露）：[`openjpeg-j2k-oob-to-arb-rw/WRITEUP.md`](https://github.com/giaoimgiao/openjpeg-j2k-oob-to-arb-rw/blob/main/WRITEUP.md)
- **B**（执行链 / 一张图到 `system()`）：[`comfyui-openjpeg-rce/README.md`](https://github.com/giaoimgiao/comfyui-openjpeg-rce/blob/main/README.md)
- 细节复现：B 的 [`REPRODUCE.md`](https://github.com/giaoimgiao/comfyui-openjpeg-rce/blob/main/REPRODUCE.md)

---

*本文件只描述两个仓库的关系与差异；两侧的实现细节各自以各自仓库文档为准。*