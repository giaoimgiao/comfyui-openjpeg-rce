# JPEG2000 (Pillow 12.3.0 / vendored openjpeg 2.5.4) 越界写 —— 完整利用链研究

> 研究目标：把 `j2k.c read_sod()` 的越界写，从 PoC 推到"远程无执行点 RCE"。
> 所有结论均为**实测字节证据**，无推测性结论。本地环境：Linux / glibc / CPython 3.12（**非 PIE**）。

## 一、漏洞根因（字节级）

```c
/* j2k.c:4676  TLM 有效则不扩容 ⇒ 数组大小 = TLM 条目数 */
tp_index = opj_calloc(l_current_max_tpm, sizeof(opj_tp_index_t));   /* 23 * 24 = 552 */
/* j2k.c:5085  写索引来自 SOT 的 TPsot 递增，与上面的分配量无关 */
cstr_index->tile_index[tile].tp_index[current_tpsno] = ...;         /* current_tpsno 可达 25 */
```

- 数组大小 = **TLM 条目数**；写索引 = **SOT 的 TPsot** ⇒ 不一致 ⇒ **越界写 3 个条目（6 个 8 字节值）**
- 落点固定：`tp_index + 0x230 / 0x238 / 0x248 / 0x250 / 0x260 / 0x268`
- **写出去的值 = 文件内偏移**（`start_pos` / `next_part_pos - 10`）⇒ 值域 `[0x70, 文件大小]`
  - ⇒ **任意 ≤ 文件大小的地址都是"可表达"的**（本链一切构造的基础）

## 二、能力矩阵（逐级验证）

| # | 原语 | 状态 | 证据 |
|---|---|---|---|
| 1 | 远程 DoS（单文件 134KB） | ✅ | `poc_dos.jp2`，`Image.open().load()` 即崩 |
| 2 | 越界写（值=文件偏移） | ✅ | 插桩 `[DBG OOB-WRITE-IMMINENT]`（6 个落点） |
| 3 | 服务器驱动写（解码器写进指定地址） | ✅ §18/§19 | 伪造 `opj_tcd_tilecomp_t` ⇒ 像素写进目标地址 |
| 4 | 类型混淆 `bytes → memoryview` | ✅ §26 | `被混淆的 B 数量 = 1 / 400` |
| 5 | **任意内存读 ⇒ ASLR 归零** | ✅ §26 | `直读 @0xa500d0 = 54ef4600...`，两次跑指针一致 |
| 6 | 远程无执行点 RCE | ⏳ 进行中 | 需"控制流目标 + 服务器侧触发"（见第七节） |

**§26 实测输出（可复现）：**

```
[*] 相邻对 = 394 / 400
[*] 释放 16 个洞（前 7 个进 tcache，第 8 个起进 unsorted/smallbin）
解码完成
  被混淆的 B 数量 = 1 / 400
   view.buf=0xa500d0  view.obj=0xa4000c  view.len=0xa500d0
   ★直读 @0xa500d0 = 54ef4600000000008000000000000000001f90...
   ★★ 指针=0x46ef54,0x901f00,0x723a08,0x46eb6c,0x901e20,0x723920
```

## 三、三个"卡很久最后靠字节证据解决"的根因（最有价值的部分）

1. **`opj_calloc` 跳过 tcache**
   `tp_index` 由 `opj_calloc` 分配 ⇒ 走 `_int_malloc` ⇒ **看不见 tcache**。
   只释放 1 个洞 ⇒ 洞躺在 tcache 里 ⇒ 数组永远从堆顶新切 ⇒ 写窗口永远盖不到目标对象。
   **修法**：排空同尺寸档 + 一次释放 **≥8 个**（前 7 个填 tcache，第 8 个起进 unsorted/smallbin）。

2. **引用泄漏**
   `pairs` 列表仍持有 D ⇒ `del hole` 引用计数不减 ⇒ **洞根本没释放**。
   **修法**：`del pairs, gold` 之后再释放。

3. **`PyMemoryViewObject` 是 `PyObject_VAR_HEAD`**
   ```
   0x00 refcnt | 0x08 ob_type | 0x10 ob_size
   0x18 mbuf   | 0x20 len      | 0x28 view.buf ★ | 0x30 view.obj | 0x38 view.len
   ```
   `view.buf` 在 **+0x28**，恰好落在两个落点之间 ⇒ 越界写无法命中。
   **修法**：越界写只负责 `ob_type`（+0x08）；**`view.buf` 用对象内容预置**（data 偏移 0x08）。

附：`mv[0]` 报 `invalid indexing of 0-dim memory`（`ndim` 语义检查）——内存已就位，读取用 `ctypes.string_at`，与利用无关。

## 四、适用性（诚实边界）

**必要条件**
- 目标走 **vendored openjpeg 2.5.4** 的 J2K 解码路径（Pillow `Image.open(.jp2)` 等）
- **glibc**（tcache / smallbin / calloc 行为）
- 上传上限 **> 11MB**（值=文件偏移 ⇒ 地址需可表达）
- **非 PIE 的 CPython**（PIE 下 type 对象在 `0x7f…` ⇒ 值不可表达 ⇒ 此链不可达）
  - 非 PIE 来源：`python3.x-nopie` 包、源码自编译（无 `-fPIE -pie`）、部分云/容器镜像

**充分性还差两条（部署相关，需按目标映射）**
- **groom 可造性**：需在同一 worker 进程内制造"排空 + 喷射 + ≥8 个同尺寸洞"
- **触发路径**：上传内容确实进入 J2K 解码器

**不适用**：PIE + ASLR + 上传 ≤10MiB ⇒ 仅 DoS 成立。

## 五、复现

```bash
# 1) DoS（任意 libc）
python3 -c "from PIL import Image; Image.open('poc_dos.jp2').load()"

# 2) 信息泄露（非 PIE CPython + glibc）
python3 exp/leak_v11.py     # 输出 被混淆的 B 数量 / view.buf / ★★ 指针=
```

## 六、文件索引

```
WRITEUP.md            完整技术文档（§0–§26，900+ 行，含全部失败数据）
poc_dos.jp2           DoS PoC（134KB，单文件）
check_target.py       目标可行性检测器
LEAK_SUCCESS.txt      信息泄露成功证据
exp/
  builder.py, base.j2k              恶意文件构造器 + 骨架
  run.sh, exp.py                    本地 RCE 演示（uid=0）
  leak_v9/v10/v11.py                信息泄露三版演进（含根因注释）
  leak_sweep.py, mk_v9b/v10/v11.py  释放点扫描 / 版本生成器
  field_align.py, endgame_*.py      伪造树路线（§20–§22）
  two_stage2.py, fake_tc.py         服务器驱动写（§18/§19）
```

## 七、RCE 下一阶段（路线）

已有 **任意读 + 内容可控的任意写 + 非 PIE 固定基址**（gadget 无 ASLR）：

- **控制流目标**：在低地址喷射缓冲区里伪造 `PyTypeObject`，`tp_repr` / `tp_dealloc` 指向 gadget
- **触发点**：让**服务器自己持有的对象**（上传缓冲）`ob_type` 指向该伪类型 ⇒ 服务器 `repr()/str()/日志/删除` 即进入 gadget
- **gadget 选型**（非 PIE ⇒ 地址固定）：优先"取 `[rdi+0x30]` 后转 `system`"这类单跳 gadget（`str`/`bytes` 的 data 指针在 +0x30/+0x20）
- 备选：`tp_dealloc = system` + 构造"对象起始即命令串"的伪造对象（配合 §18 服务器驱动写）

## 八、披露

本仓库当前为 **private**。openjpeg 上游/发行版修复前不建议公开（满足上述条件的部署可达成无执行点 RCE）。