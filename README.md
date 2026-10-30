# unpack-ue-mobile-game

Cursor Agent Skill：拆包虚幻引擎 4/5 安卓游戏，并找回 IoStore 的 AES 密钥。它指导代理定位 `.utoc` / `.ucas` / `.pak` 容器、取得运行时密钥、校验密钥，并导出网格与贴图。

流程已在一款 UE 4.27 安卓游戏（安卓模拟器）上端到端验证。难点几乎总是 AES 密钥；本 Skill 按代价从低到高依次尝试。

本 Skill 设置了 `disable-model-invocation: true`。需要显式点名（例如 `@unpack-ue-mobile-game`），代理才会加载 `SKILL.md`。

## 免责声明

本仓库仅供学习与技术交流，请只在你拥有或已获授权分析的游戏上使用。

若其中内容侵犯了你的合法权益，请通过 GitHub Issues 或站内联系告知。我在收到通知后会尽快核实，并第一时间删除相关内容。

## 目录

| 路径 | 作用 |
|------|------|
| [SKILL.md](SKILL.md) | 代理工作流：检查清单与分步说明 |
| [reference.md](reference.md) | 字节布局、偏移、Oodle 配置、厂商改动 |
| [scripts/find-ue4-aes-key-arm64-v8a.py](scripts/find-ue4-aes-key-arm64-v8a.py) | IDA Python：对 `libUE4.so` 做静态特征扫描 |
| [scripts/scan_mem_key.py](scripts/scan_mem_key.py) | 以 ContainerId 为锚点扫描 `/proc/<pid>/mem` |

## 适用场景

- 从 UE 安卓游戏中提取三维模型、贴图或其他资源
- `.utoc` / `.ucas` / `.pak` 被 AES 加密
- 需要查找 UE pak 或 IoStore 的 AES 密钥

## 工作流

代理按下列顺序执行。细节、易错点和厂商改动见 `SKILL.md` 与 `reference.md`。

1. **定位容器** — APK（常把 zip 伪装成图片，例如 `assets/main.obb.png`）、OBB，再是已 root 的模拟器或真机应用数据。资源可能按需下载（`12_<id>.ucas`）。先拷到本地再处理。排除 `*_hdiff` 补丁，避免盖住同名资源。
2. **确认引擎版本** — `libUE4.so` 里的版本字符串，或 `.utoc` 偏移 16 处的 IoStore TOC 版本字节（`3` = UE 4.27 / UE 5.0，`2` = 4.26）。压缩几乎总是 Oodle。
3. **获取 AES 密钥**，从省事到费事：
   - **A. 已公开的密钥** — 社区列表（FModel、cark、UEViewer）。
   - **B. IDA 静态扫描** — 对 arm64-v8a 的 `libUE4.so` 运行 `scripts/find-ue4-aes-key-arm64-v8a.py`。仅当密钥是嵌入的常量时有效。
   - **C. Frida Hook** — 真 arm64 设备上通常可行。x86 安卓模拟器用 Houdini 翻译 `libUE4.so`：注入 arm64 Frida 会让 `libhoudini.so` 崩溃，x64 Frida server 也看不到翻译后的指令。此时改走 D。
   - **D. 实时内存扫描** — 只需 root ADB，不注入。以每个容器的 `ContainerId`（`.utoc` 偏移 `0x38` 的 `u64`）为锚，收集高熵的 32 字节窗口，按出现次数排序。`EncryptionKeyGuid` 全零的容器共用一把全局密钥。
4. **校验** — 用 AES-256-ECB 解密 `.utoc` 的目录索引，确认为 `FIoDirectoryIndexResource`。不能只看出现次数。挂载点可以是空字符串（长度为 1，只有一个空字节）。
5. **合并并导出** — 把底包容器和按需下载放到同一目录。优先用 FModel（自定义/未识别游戏、引擎版本、AES 密钥）。FModel 导出 glTF/OBJ/PSK，不导出 FBX；需要 FBX 时再在 Blender 里转 glTF。
6. **厂商定制** — 原版 FModel/CUE4Parse 可能失败。参考版本额外加密了 OffsetAndLength 表，`.ucas` 块虽标了 Encrypted 却是明文，挂载点为空，顶点是 16 位量化。需要把 TOC 规范化，或自己写读取器。见 `reference.md`。

## 脚本

### 静态扫描（IDA）

作者 GHFear / IllusorySoftware。在 IDA 中加载 arm64-v8a 的 `libUE4.so`，然后 **File → Script file…** 运行：

```text
scripts/find-ue4-aes-key-arm64-v8a.py
```

脚本匹配 pak 加密密钥委托的 ADRP/LDR 特征，跟到回调，并打印回调引用的 32 字节密钥。密钥若在运行时拼装或解密，此脚本找不到。

### 内存扫描

需要 root ADB、Python 3、`numpy` 和 `pycryptodome`。先在游戏里打开关卡或车辆，让密钥完成注册，然后：

```bash
pip install numpy pycryptodome

python scripts/scan_mem_key.py \
  --pid 1769 \
  --utoc path/to/any_encrypted.utoc \
  --ids-from path/to/utoc_dir \
  --adb adb \
  --serial 127.0.0.1:21503
```

| 参数 | 含义 |
|------|------|
| `--pid` | 游戏进程号 |
| `--utoc` | 用来校验候选密钥的一份已加密 `.utoc` |
| `--ids-from` | `.utoc` 所在目录；从偏移 `0x38` 读取 ContainerId |
| `--adb` | ADB 可执行文件（默认 `adb`） |
| `--serial` | 设备序列号，例如模拟器端口 |
| `--lib` | maps 过滤时保留的引擎库名（默认 `libUE4`） |
| `--su` | `adbd` 非 root 时，用 `su -c` 包一层 `dd` |

命中时打印 `KEY FOUND` 和解密后的目录索引开头。若没有通过校验，脚本会按出现次数列出前若干候选，供人工查看。

## 依赖

- Python 3、`numpy`、`pycryptodome`（内存扫描）
- 已加载 arm64-v8a `libUE4.so` 的 IDA（静态扫描）
- 已 root 的模拟器或真机，以及 ADB（内存扫描）
- FModel（或自写的 IoStore 读取器），以及用于 Oodle 的 `oo2core_*_win64.dll`
- 可选：Blender，用于 glTF 转 FBX

## 使用范围

仅用于你拥有或获准分析的游戏。本 Skill 从你已有的进程和文件中恢复密钥与资源，不绕过商店登录、账号校验或在线服务。

---

# English

Cursor Agent Skill for unpacking Unreal Engine 4/5 Android games and recovering the IoStore AES key. It walks an agent through locating `.utoc` / `.ucas` / `.pak` containers, obtaining the runtime key, validating it, and exporting meshes and textures.

The workflow was validated end-to-end on a UE 4.27 Android title running in an Android emulator. The hard part is almost always the AES key; the skill tries the cheaper avenues first.

This skill has `disable-model-invocation: true`. Name it explicitly (for example `@unpack-ue-mobile-game`) so the agent loads `SKILL.md`.

## Disclaimer

This repository is for learning and technical discussion only. Use it solely on games you own or are authorized to analyze.

If anything here infringes your rights, please tell me through a GitHub issue or a message on GitHub. Once notified, I will look into it promptly and remove the material right away.

## Contents

| Path | Role |
|------|------|
| [SKILL.md](SKILL.md) | Agent workflow: checklist and ordered steps |
| [reference.md](reference.md) | Byte layouts, offsets, Oodle setup, vendor pitfalls |
| [scripts/find-ue4-aes-key-arm64-v8a.py](scripts/find-ue4-aes-key-arm64-v8a.py) | IDA Python: static signature scan of `libUE4.so` |
| [scripts/scan_mem_key.py](scripts/scan_mem_key.py) | Live `/proc/<pid>/mem` scan anchored on ContainerIds |

## When to use it

- Extracting 3D models, textures, or other assets from a UE Android game
- A `.utoc` / `.ucas` / `.pak` set is AES-encrypted
- You need to find a UE pak or IoStore AES key

## Workflow

The agent follows this order. Details, gotchas, and vendor notes live in `SKILL.md` and `reference.md`.

1. **Locate containers** — APK (often a zip disguised as an image, e.g. `assets/main.obb.png`), OBB, then rooted emulator/device app data. Games may download assets on demand (`12_<id>.ucas`). Copy files locally before working on them. Skip `*_hdiff` patches.
2. **Identify the engine** — version string in `libUE4.so`, or the IoStore TOC version byte at offset 16 of a `.utoc` (`3` = UE 4.27 / UE 5.0, `2` = 4.26). Compression is almost always Oodle.
3. **Get the AES key**, cheapest first:
   - **A. Published key** — community lists (FModel, cark, UEViewer).
   - **B. Static IDA scan** — `scripts/find-ue4-aes-key-arm64-v8a.py` on arm64-v8a `libUE4.so`. Works only when the key is an embedded constant.
   - **C. Frida hook** — reliable on a real arm64 device. On x86 Android emulators Houdini translates `libUE4.so`; native arm64 Frida crashes `libhoudini.so`, and the x64 Frida server does not see the translated instructions. Skip to D.
   - **D. Live memory scan** — root ADB, no injection. Anchor on each container's `ContainerId` (`u64` at `.utoc` offset `0x38`), harvest high-entropy 32-byte windows, rank by frequency. Containers with an all-zero `EncryptionKeyGuid` share one global key.
4. **Validate** — AES-256-ECB decrypt the `.utoc` directory index and check that it parses as an `FIoDirectoryIndexResource`. Frequency alone is not enough. An empty mount point (length 1, a single null) is valid.
5. **Merge and export** — one folder of base containers plus on-demand downloads. Try FModel first (custom/undetected game, engine version, AES key). FModel exports glTF/OBJ/PSK, not FBX; convert glTF in Blender if you need FBX.
6. **Vendor customizations** — stock FModel/CUE4Parse can fail. The reference build extra-encrypted the OffsetAndLength table, left `.ucas` blocks plaintext despite the Encrypted flag, used an empty mount point, and stored 16-bit quantized vertices. Normalize the TOC, or write a direct reader. See `reference.md`.

## Scripts

### Static scan (IDA)

By GHFear / IllusorySoftware. In IDA, load the arm64-v8a `libUE4.so`, then **File → Script file…** and run:

```text
scripts/find-ue4-aes-key-arm64-v8a.py
```

It matches the ADRP/LDR signature of the pak encryption-key delegate, follows it to the callback, and prints the 32-byte key that callback references. If the key is assembled or decrypted at runtime, this script will not find it.

### Memory scan

Requires root ADB, Python 3, `numpy`, and `pycryptodome`. Open a level or vehicle in-game first so the key is registered, then:

```bash
pip install numpy pycryptodome

python scripts/scan_mem_key.py \
  --pid 1769 \
  --utoc path/to/any_encrypted.utoc \
  --ids-from path/to/utoc_dir \
  --adb adb \
  --serial 127.0.0.1:21503
```

| Flag | Meaning |
|------|---------|
| `--pid` | Game process id |
| `--utoc` | One encrypted `.utoc` used to validate candidates |
| `--ids-from` | Folder of `.utoc` files; ContainerIds are read from offset `0x38` |
| `--adb` | ADB executable (default `adb`) |
| `--serial` | Device serial, e.g. an emulator port |
| `--lib` | Engine library name kept in the maps filter (default `libUE4`) |
| `--su` | Wrap `dd` in `su -c` when `adbd` is not root |

A hit prints `KEY FOUND` plus the decrypted directory-index head. If nothing validates, the script prints the top candidates by frequency for manual inspection.

## Requirements

- Python 3, `numpy`, `pycryptodome` (memory scan)
- IDA with the arm64-v8a `libUE4.so` loaded (static scan)
- Rooted emulator or device, and ADB (memory scan)
- FModel (or a custom IoStore reader) plus `oo2core_*_win64.dll` for Oodle
- Optional: Blender, for glTF → FBX

## Scope

Use this on games you own or are allowed to analyze. The skill recovers keys and assets from a process and files you already have; it does not bypass store login, account checks, or online services.
