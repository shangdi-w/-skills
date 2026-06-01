---
name: hacker-asm-decompile
description: 全平台反编译与逆向工程工具链 — JAR/APK/EXE/ELF/Mach-O/.NET/JS/WASM/Python/PHP/Electron/Unity/Flutter/Go/IPA + 脱壳(UPX/Themida/VMProtect) + Rust/Swift/Lua + LLM辅助逆向 + 固件分析。24 类全覆盖,实战命令即用。
---

# 全平台反编译与逆向工程

> 覆盖 JAR · APK · EXE/DLL · ELF · Mach-O · .NET · JS/WASM · Python · PHP · Electron · Unity · Flutter · Go · IPA · 脱壳 · Rust · Swift · Lua · 固件 · LLM辅助 — 24 大类

---

## 🔴 法律声明

**本 Skill 仅供授权安全测试、学术研究及教育目的使用。** 使用前必须获得目标系统所有者的明确书面授权。严禁用于任何未经授权的渗透测试、逆向工程、入侵或非法活动。使用者须自行承担所有法律后果。详见仓库 [README](../README.md)。

---

## 一、JAR / Java 反编译

### 工具矩阵

| 工具 | 版本 | 状态 | 核心用途 |
|------|------|------|----------|
| **jadx** | v1.5.5 | 🔥 活跃 | GUI+CLI 首选，支持 jar/dex/apk/aar |
| **CFR** | 0.152 | ⚠️ 停更 | CLI 反编译质量最高，混淆对抗最强 |
| **Procyon** | v0.6.0 | 🟡 低活跃 | 枚举/泛型处理细腻 |
| **Fernflower** | IDEA 内置 | 🟢 维护中 | IntelliJ 默认引擎,行号精确 |
| **Bytecode Viewer** | v2.13.2 | 🟢 活跃 | 6 引擎 + 字节码编辑,瑞士军刀 |
| **Recaf** | 4.0.0-alpha | 🟢 活跃 | 现代字节码 IDE,直接编辑字节码 |
| **ASM** | 9.7 | 🟢 活跃 | 程序化字节码操作框架 |

### jadx CLI

```bash
# 基本反编译
jadx -d output_dir target.jar
jadx -d output_dir app.apk

# 反混淆（重命名类/方法/字段）
jadx --deobf -d output_dir target.jar
jadx --deobf --deobf-min 3 -d output_dir target.jar

# 导出 Gradle 项目
jadx --export-gradle -d output_dir target.jar

# 仅反编译特定类
jadx -d output_dir -e 'com\.example\..*' target.jar

# 显示 fallback 字节码（反编译失败的代码以字节码展示）
jadx --show-bad-code -d output_dir target.jar

# 多线程加速
jadx -j 8 -d output_dir target.jar

# 跳过资源
jadx --no-res -d output_dir target.jar
```

### jadx GUI

- `Ctrl+Shift+F` — 全文搜索
- `Ctrl+N` — 类名搜索
- 右键 → Find Usage — 交叉引用
- 导航栏直接输入类名跳转

### CFR CLI（对抗重度混淆首选）

```bash
# 基本反编译
java -jar cfr.jar target.jar --outputdir output_dir

# 完整推荐命令（应对重度混淆）
java -jar cfr.jar target.jar \
  --outputdir out/ \
  --caseinsensitivefs true \
  --decodestringswitch true \
  --decodelambdas true \
  --tryanalyse true \
  --hideutf true \
  --removebadgenerics true

# 反编译单个 class
java -jar cfr.jar MyClass.class

# 反编译特定类（正则）
java -jar cfr.jar target.jar --filter 'com.example.*'

# 显示字节码注释
java -jar cfr.jar target.jar --showbytecode true

# 展开 switch 混淆
java -jar cfr.jar target.jar --forcestringswitch true --forceedswitches true
```

### 反混淆对抗

| 混淆器 | 混淆技术 | 对抗方法 |
|--------|----------|----------|
| **Zelix KlassMaster** | 控制流扁平化/字符串加密/类加密 | CFR unflatten + JVMTI Agent 运行时 dump |
| **Allatori** | 字符串加密/方法重命名/水印 | 提取 AllatoriDecryptor 写解密脚本 |
| **DashO** | 控制流+字符串+重载诱导 | CFR + jadx + 调用上下文分析 |
| **Stringer** | 全 class 加密存储 | Frida/JDB 运行时 dump |
| **ProGuard/R8** | 弱混淆 | jadx 开箱还原 90% |

**通用技巧**：
- 多引擎联合对比：jadx + CFR 各出一份,查漏补缺
- 字符串搜索大法：搜 `http`/`AES`/`Cipher`/`SELECT`/`secret`/`key`/`token`/`password`
- 运行时动态分析：在 String 构造打断点,捕获所有解密后字符串
- 字节码 Patch：Recaf/Bytecode Viewer 手动 NOP 反调试、修改 if 绕过校验

---

## 二、APK / Android 反编译

### 结构
APK = ZIP(`AndroidManifest.xml` + `classes.dex` + `res/` + `resources.arsc` + `lib/*.so` + `META-INF/` + `assets/`)

### 静态分析

**apktool** — 解包/重打包 smali 层
```bash
apktool d app.apk -o apk_out      # 解包 (smali + 解码资源)
apktool b apk_out -o patched.apk   # 重打包
# 然后 zipalign + apksigner 签名
```

**jadx** — DEX → Java（首选）
```bash
jadx-gui app.apk                   # 图形界面
jadx -d out app.apk                # 命令行
jadx --deobf -d out app.apk        # 带反混淆
```

**dex2jar + JD-GUI** — 经典备用链
```bash
d2j-dex2jar classes.dex -o output.jar
# JD-GUI 打开 output.jar
```

**smali/baksmali** — 字节码级修改
```bash
baksmali d classes.dex -o smali_out    # 反汇编
# 修改 smali 代码（插日志/跳验证）
smali a smali_out -o classes.dex        # 汇编回 dex
```

**Androguard** — Python 自动化分析
```python
from androguard.misc import AnalyzeAPK
apk, dalvik, analysis = AnalyzeAPK("app.apk")
print(apk.get_permissions())
```

**MobSF** — 自动化安全扫描
```bash
docker run -p 8000:8000 opensecurity/mobile-security-framework-mobsf
# Web UI → 上传 APK → 生成 PDF 报告
```

### 动态分析

**Frida** — 跨平台动态插桩
```bash
frida -U -l hook.js com.example.app   # USB 连接手机
# hook.js 示例：Hook 加密函数、绕过 SSL Pinning
Java.perform(function() {
    var Cipher = Java.use("javax.crypto.Cipher");
    Cipher.doFinal.overload('[B').implementation = function(data) {
        console.log("doFinal: " + bytesToHex(data));
        return this.doFinal(data);
    };
});
```

**Objection** — 基于 Frida 的交互式 REPL
```bash
objection -g com.example.app explore
# android sslpinning disable       一键绕过证书绑定
# android hooking list classes     列出所有类
# android hooking watch class com.example.Crypto   监控类方法调用
```

### Native .so 分析
- **Ghidra**: File → Import File → Auto Analyze
- **IDA Pro**: 配合 findcrypt 插件定位加密常量
- **radare2**: `r2 -A libnative.so` → `afl` 列函数 → `pdf @sym.func`

---

## 三、IPA / iOS 反编译

### IPA 解密（前置步骤）

```bash
# Clutch（越狱设备）
Clutch -i                    # 列出已安装应用
Clutch -d <bundle_id>        # 解密并导出 IPA

# frida-ios-dump（推荐）
python3 dump.py <bundle_id>  # Frida 注入 dump

# dumpdecrypted.dylib（手动注入）
DYLD_INSERT_LIBRARIES=dumpdecrypted.dylib /var/.../App
```

### 静态分析

```bash
# class-dump — 提取 ObjC 类头文件
class-dump -H MyApp -o headers/

# Hopper Disassembler — macOS 原生反编译器
# 图形界面 → 伪代码 + CFG 生成

# Ghidra — 开源 NSA 框架
# File → Import → Mach-O → Auto Analyze
```

### 动态分析
```bash
frida -U -l hook.js com.example.app
objection -g com.example.app explore
# ios sslpinning disable
```

---

## 四、EXE / DLL（Windows）反编译

### 静态分析器

**Ghidra** ⭐69k — NSA 开源首选
```
File → Import File → 选 PE → Auto Analyze
按 F 定义函数 / L 重命名 / C 清除重新反汇编
导出伪 C 代码
```

**IDA Pro / IDA Freeware**
- Pro 含 Hex-Rays Decompiler（伪 C）
- Freeware 仅 x86/x64 反汇编,无 decompiler
- FLIRT 签名库自动识别标准库

**radare2 / rizin** — 命令行轻量
```bash
r2 -A target.exe
aaa / aaaa          # 自动分析（深度递增）
afl                 # 列出所有函数
pdf @main           # 反汇编 main 函数
izz                 # 列出所有字符串
/ string            # 搜索字符串
```
GUI 前端: **Cutter** (基于 rizin,⭐18.9k)

### 动态调试器

**x64dbg** ⭐48.5k — Windows 首选
```
F2 断点 / F9 运行 / F7 步入 / F8 步过
Ctrl+G 跳转地址
右键 → Find references to → 交叉引用
Scylla 插件重建 IAT（脱壳用）
```

---

## 五、.NET 专用反编译

### 工具矩阵

| 工具 | Stars | 核心 |
|------|-------|------|
| **dnSpy/dnSpyEx** | ⭐29.5k | 反编译+调试+修改 三合一 |
| **ILSpy** | ⭐25.3k | 跨平台,可做库嵌入 |
| **dotPeek** | JetBrains | 免费,导出 VS 项目 |
| **de4dot** | ⭐7.4k | 去混淆：Confuser/Dotfuscator/.NET Reactor 等 |

### 实战流程

```bash
# 1. 先去混淆
de4dot target.exe -o cleaned.exe

# 2. dnSpy 打开 → 查看 C# 源码
# 3. 右键 → Edit Method → 修改代码 → 重新编译
# 4. File → Save Module → 保存修改后的 exe
```

### ConfuserEx 脱壳
```bash
# de4dot 自动检测
de4dot --detect obfuscated.exe
de4dot obfuscated.exe -o cleaned.exe

# 若 de4dot 失败 → dnSpy 手动：
# 1. 定位 Confuser 的 Module .cctor
# 2. 在解密出口打断点
# 3. 运行后 dump 内存
# 4. NoFuserEx / ConfuserEx-Unpacker 等专用工具
```

---

## 六、ELF（Linux）反编译

### 静态分析
```bash
# Ghidra（全架构支持）
# File → Import → ELF → Auto Analyze

# radare2 快速分析
r2 -A ./binary
afl~main              # 找 main 函数（用正则过滤）
pdf @main             # 反汇编 main
izz | grep -i flag    # 搜索 flag 字符串

# objdump 线性反汇编
objdump -d ./binary    # 全部 .text
objdump -d -M intel ./binary | less
readelf -a ./binary    # ELF 头完整信息
```

### 动态调试
```bash
# GDB + GEF / pwndbg
gdb -q ./binary
break *main
run
vmmap                  # 内存布局（GEF）
checksec               # 安全机制检查（checksec 工具）

# strace / ltrace
strace ./binary        # 系统调用追踪
ltrace ./binary        # 库函数调用追踪

# LD_PRELOAD 注入
LD_PRELOAD=./hook.so ./binary
```

---

## 七、Mach-O（macOS）反编译

### 文件分析
```bash
# 查看 FAT Binary 架构
lipo -info ./binary

# 提取单架构
lipo -extract x86_64 ./binary -o output_x64
lipo -extract arm64 ./binary -o output_arm64

# 查看依赖
otool -L ./binary

# 查看签名
codesign -dvvv ./binary

# 列出符号
nm ./binary

# 反汇编
otool -tV ./binary
```

### 专用工具
- **Hopper** — macOS 原生图形化反编译（价格适中,ObjC/Swift 支持极佳）
- **class-dump** — 导出 ObjC 类声明 `class-dump -H MyApp -o headers/`
- **lldb** — macOS 自带调试器 `lldb ./binary`

---

## 八、JavaScript 反混淆

### 工具链

```bash
# de4js — 在线反混淆,支持多种混淆器
# URL: https://lelinhtinh.github.io/de4js/

# synchrony — 基于 Babel AST 的程序化反混淆
npm install -g synchrony
synchrony obfuscated.js -o cleaned.js

# webcrack — Webpack bundle 解包 + JS 反混淆
npm install -g webcrack
webcrack bundle.js -o unpacked/

# js-beautify — 格式化
npx js-beautify obfuscated.js -o formatted.js
```

### 混淆特征与对抗

| 混淆器 | 特征 | 对抗 |
|--------|------|------|
| **javascript-obfuscator** | 十六进制字符串数组 + 位移 | de4js / synchrony |
| **obfuscator.io** | `_0x` 前缀变量 + 数组旋转 | synchrony AST 还原 |
| **JSFuck** | 仅 `[]()!+` 六字符 | 直接 eval 或在线解码 |
| **aaencode** | 颜文字 | 在线解码器 |
| **Packer (Dean Edwards)** | `eval(function(p,a,c,k,e,d)` | de4js |
| **Webpack** | `__webpack_require__` | webcrack 拆包 |
| **V8 bytecode (bytenode)** | `.jsc` 文件 | v8-bytecode-decompiler |

### DevTools 强制开启（Electron/Web应用）
```bash
# Electron 远程调试
./app --remote-debugging-port=9222
# 然后 Chrome 打开 chrome://inspect

# 注入代码强制打开 DevTools
# Frida 或修改 main.js:
require('electron').remote.getCurrentWindow().webContents.openDevTools()
```

---

## 九、WebAssembly（WASM）反编译

```bash
# WABT 工具集
git clone https://github.com/WebAssembly/wabt

# wasm → WAT（文本格式汇编）
wasm2wat module.wasm -o module.wat

# wasm → C（伪代码）
wasm-decompile module.wasm -o module.dcmp

# wasm → C 源码（完整转换）
wasm2c module.wasm -o module.c

# 查看导出/导入函数
wasm-objdump -x module.wasm
wasm-objdump -d module.wasm   # 反汇编
```

在 Ghidra 中分析 WASM：安装 `ghidra-wasm-plugin` → Import → 按 WebAssembly 格式加载。

---

## 十、Python 反编译

### .pyc 反编译

```bash
# uncompyle6（Python 2.7-3.8）
pip install uncompyle6
uncompyle6 target.pyc > target.py

# decompyle3（Python 3.7-3.9）
pip install decompyle3
decompyle3 target.pyc

# pycdc（更强,支持 3.10+）
git clone https://github.com/zrax/pycdc
cd pycdc && cmake . && make
./pycdc target.pyc

# pycdas（反汇编 .pyc 查看字节码）
./pycdas target.pyc
```

### PyInstaller 解包

```bash
# pyinstxtractor — 提取 .pyc
python pyinstxtractor.py target.exe
# → 生成 target.exe_extracted/ 目录

# 从提取目录恢复入口 pyc
# 1. 找到 main 相关的 pyc 文件（缺少 magic header）
# 2. 从 struct.pyc 复制前 16 字节 magic header 补到目标
# 3. uncompyle6 / pycdc 反编译

# pyi-archive_viewer（PyInstaller 自带）
python -m PyInstaller.utils.cliutils.archive_viewer target.exe
```

### Nuitka 解包
```bash
# Nuitka 使用 SX 格式,工具较少
# strings 搜索 Python 代码片段
strings target.exe | grep -E "(import|def |class )"
```

### 对抗方案
- **Cython 编译**：无直接反编译工具,需 Ghidra/IDA 分析 .so/.pyd
- **PyArmor/Oxyry**：内存 dump + 手动分析字节码
- **Py2Exe**：类似 PyInstaller,用 `pyinstxtractor` 同类工具

---

## 十一、PHP 反编译

```bash
# PHP 通常不被"编译",但以下场景需要逆向：

# 1. OPCache 文件（.bin）逆向
php -d opcache.file_cache=/tmp/opcache script.php
# OPCache 文件位于 opcache 缓存目录

# 2. ionCube 解密
# ionCube 是 PHP 商业加密方案
# 对抗：使用 ionCube 官方解码器（需 license）或动态 hook Zend Engine

# 3. SourceGuardian 解密
# 对抗：PHP 扩展级 hook zend_compile_file

# 4. Phalanger / PeachPie（.NET 编译的 PHP）
# 已编译为 .NET IL → 用 dnSpy 反编译

# 5. PHP 混淆器（如 php-obfuscator）
# 本质是 eval + base64 → 手动 decode + 格式化

# 6. 在线 PHP 解密
# https://www.unphp.net/ 等在线平台
```

---

## 十二、Electron / asar 逆向

```bash
# asar 解包
npm install -g @electron/asar
asar extract app.asar ./output
asar list app.asar                    # 列出文件
asar extract-file app.asar main.js    # 提取单文件

# webpack 拆包
npm install -g webcrack
webcrack output/main.js -o unpacked/

# JS 反混淆
npm install -g synchrony
synchrony unpacked/app.js -o cleaned.js
```

### 加密 asar 对抗
```bash
# 1. 找到解密逻辑（通常在 app.asar 外的 main.js 或 native addon）
# 2. Frida hook asar 读取函数
# 3. patch 解密函数,导出明文

# DevTools 强制开启
./app --remote-debugging-port=9222
```

### V8 Snapshot 逆向
```bash
# electron-v8snapshot-parser（解析 .bin/.blob）
# electron-fuzzer（解析 V8 快照）
```

---

## 十三、Unity 游戏逆向

### IL2CPP 后端

```bash
# Il2CppDumper — 核心工具（⭐9k）
# 从 global-metadata.dat + libil2cpp.so 恢复 dump.cs
# 同时生成 IDA/Ghidra 脚本自动重命名函数
./Il2CppDumper libil2cpp.so global-metadata.dat output/

# 生成：dump.cs（C# 伪代码）+ script.py（IDA 脚本）+ script_ghidra.py
```

### Mono 后端

```bash
# dnSpy 直接打开 Assembly-CSharp.dll
# 完全还原 C# 源码
```

### BeeByte 混淆对抗
- IL2CPP_PWN：过滤 BeeByte 注入的垃圾类型
- 动态 dump：hook `il2cpp_codegen_initialize_method`

---

## 十四、Flutter / Dart 逆向

```bash
# blutter（⭐2.4k）— 解析 Dart AOT snapshot
blutter libapp.so output/

# reFlutter（⭐2.6k）— 网络拦截 + Hook
# Doldrums（⭐858）— 解析 kernel snapshot

# Frida 辅助 dump
frida -U -l dump.dart.js com.example.flutterapp
```

### Debug/Profile 模式
- `kernel_blob.bin` 包含可读 AST
- 使用 Dart SDK `pkg/vm` 工具解析

### 混淆对抗
- `--obfuscate` 标志 → 符号被短字符串替换
- blutter 可部分恢复,结合动态分析

---

## 十五、Go 二进制逆向

### 符号恢复

```bash
# GoReSym（⭐998）— stripped 符号恢复
GoReSym binary -o symbols.json
# 输出 JSON → 导入 IDA/Ghidra

# go_parser（⭐1.3k） — IDA Pro 插件
# 自动解析 pclntab + moduledata

# IDAGolangHelper（⭐1.1k）— 另一套 IDA 脚本

# Ghidra_GolangAnalyzerExtension（⭐239）— Ghidra 插件
```

### 反编译
```bash
# Ghidra: File → Import → ELF/PE → Auto Analyze
# 配合 GoReSym 导入符号表

# reko（⭐2.6k）— 通用二进制反编译器,支持 Go
reko-decompile binary -o output.c

# IDA Pro + Hex-Rays + go_parser 插件（商业最佳）
```

### Web 框架识别
```bash
strings binary | grep -E "(gin|echo|fiber|beego|iris)"
# 快速定位路由注册 → 跟进 handler 函数
```

---

## 十六、Tauri 逆向

```bash
# dredd — 专用逆向工具
dredd app.tauri -o output/

# 手动提取：
strings app | grep -E "\.(html|js|css)"   # 找嵌入资源
binwalk -e app                            # 自动提取
```

- 前端资源通常嵌入在 Rust 二进制中
- Rust 后端用 Ghidra + rust-reversing 插件
- 函数名恢复：`rustfilt < mangled_name`

---

## 十七、通用辅助工具

| 工具 | 核心用途 |
|------|----------|
| **Frida** | 跨平台动态插桩,支持 Android/iOS/Windows/macOS/Linux |
| **Ghidra** | NSA 开源全架构反编译器,Java GUI |
| **radare2/rizin** | 命令行轻量逆向,极速 triage |
| **Cutter** | rizin GUI 前端 |
| **Unicorn Engine** | CPU 模拟器,无文件脱壳 |
| **binwalk** | 固件/二进制资源提取 |
| **strings** | 最直接的字符串提取 |
| **strace/ltrace** | 系统调用/库函数追踪 |

---

## 十八、快速决策表

| 你要逆向什么 | 首选工具 |
|-------------|----------|
| Java / JAR / AAR | jadx GUI + CFR CLI |
| APK / AAB / DEX | jadx + apktool + Frida |
| iOS IPA | frida-ios-dump + class-dump + Hopper |
| Windows EXE/DLL | x64dbg（调试）+ Ghidra（静态） |
| .NET EXE/DLL | de4dot → dnSpy |
| Linux ELF | Ghidra + radare2 + GDB+GEF |
| macOS Mach-O | Ghidra + Hopper + lldb |
| JavaScript 混淆 | webcrack + synchrony + de4js |
| WebAssembly | wabt wasm2wat + wasm-decompile |
| Python .pyc | pycdc + uncompyle6 |
| PyInstaller | pyinstxtractor → pycdc |
| PHP 加密 | unphp 在线 + 动态 hook |
| Electron asar | asar extract → webcrack → synchrony |
| Unity IL2CPP | Il2CppDumper → Ghidra/IDA |
| Unity Mono | dnSpy |
| Flutter/Dart | blutter + reFlutter + Frida |
| Go 二进制 | GoReSym → Ghidra/IDA |
| Tauri | dredd + Ghidra |
| Rust 二进制 | rustfilt + Ghidra |
| Lua/LuaJIT | unluac / luajit-decomp |
| Swift/Kotlin Native | swift-demangle + Hopper / Ghidra |
| 固件/IoT | binwalk → unblob → Ghidra |
| 脱壳 | DIE 识别 → x64dbg+Scylla dump |
| LLM 辅助 | Gepetto(IDA) / Ghidra MCP / dogbolt.org |
| 快速 triage | strings + radare2 + binwalk |

---

## 十九、通用脱壳技术

### 壳识别

```bash
# Detect-It-Easy (DIE) — 识别 200+ 种壳/编译器
diec target.exe

# PEiD 风格特征检测
# UPX: magic "UPX0"/"UPX1" section, pushad 开头
# ASPack: pushad → 循环 → popad + jmp OEP
# Themida: 多层入口, VM 字节码解释器
```

### UPX

```bash
# 官方解压（仅限未修改 UPX）
upx -d target.exe

# 手动脱壳（改过 magix 头或变种）
# x64dbg 加载 → 搜索 tail jump (大跳转) / POPAD
# → 定位 OEP → Scylla dump + IAT 修复
```

### Scylla — IAT 重建（⭐1.4k `NtQuery/Scylla`）

```
x64dbg → 停在 OEP → 插件 → Scylla
→ IAT AutoSearch → Get Imports → Fix Dump
→ 选 dump 文件 → 生成 _SCY.exe
```

### PE-bear — PE 结构修复（⭐3.6k `hasherezade/pe-bear`）

```
手动修复 section raw/virtual size 对齐
重建导入表/重定位表
查看/编辑资源
```

### Unicorn 模拟脱壳

| 工具 | 用途 |
|------|------|
| **Dumpulator** (⭐865) | Unicorn 内存模拟,提取配置/解密 payload |
| **Qiling Framework** (⭐5.9k) | PE/ELF 全系统模拟,自动化脱壳 |
| **Speakeasy** (⭐2k) | Mandiant 出品,Windows 内核+用户态模拟 |
| **flare-emu** (⭐949) | IDA Pro 插件,Unicorn 模拟执行函数 |

### 强壳对抗

| 壳 | 工具/方法 |
|----|----------|
| **Themida** | TitanHide(内核反反调试) + ScyllaHide + OEP 硬件断点 → dump |
| **VMProtect** | VMHunt trace VM handler / ScyllaHide + OEP dump |
| **Enigma** | EnigmaVBUnpacker / CreateProcessInternalW 断点 |

---

## 二十、Rust 独立二进制逆向

```bash
# rustfilt — demangle Rust 符号（类似 c++filt）
cargo install rustfilt
nm binary | rustfilt
strings binary | rustfilt

# 提取 Cargo 依赖信息
strings binary | grep -E "(crate|version|dependency)"
```

### Ghidra 分析要点

- 搜索 `__rust_alloc` / `__rust_dealloc` → 反向追踪业务函数调用链
- 标注 Rust 标准库函数签名：`Vec::push`、`String::as_str`、`Box::new`
- Rust 胖指针（&str = 8B ptr + 8B len）→ 手动标记结构体
- DWARF 含 `rustc` 标识 + 完整源码路径（debug 模式）
- 恢复 main: 追踪 `std::rt::lang_start` → `rust_main`

---

## 二十一、Lua / LuaJIT 逆向

### Lua 标准字节码

```bash
# unluac — 支持 Lua 5.0-5.4
java -jar unluac.jar input.luac > output.lua

# luac -s 剥离调试信息 = 无法恢复变量名/行号
```

### LuaJIT（与标准 Lua 完全不兼容）

```bash
# luajit-decomp（⭐272）— 支持 LuaJIT 2.0/2.1
luajit-decomp input.ljbc > output.lua

# 字节码列表（反汇编）
luajit -bl input.lua
luajit -b -l input.lua output.lst
```

### 游戏 Modding 常见场景

| 游戏/引擎 | 解包 | 反编译 |
|-----------|------|--------|
| **GMod** | gmad 解包器 | gluasteal 提取 glua → gluac 反编译 |
| **WoW** | WoW Lua Extractor | Blizzard 自定义 Lua 实现 |
| **Roblox** | Roblox-Client-Tracker | rbx2source dump 函数 |
| **Factorio** | 解包资源 | 专用反编译器（自定义字节码） |

**加密 Lua 对抗**：游戏常用 XXTEA/AES 加密 `.luac`，在 `luaL_loadbuffer` 调用点下断 dump 解密后的字节码。

---

## 二十二、Kotlin Native / Swift 独立逆向

### Swift

```bash
# swift-demangle — 还原混淆符号
xcrun swift-demangle "$sSq"          # → Optional
nm binary | xcrun swift-demangle

# class-dump (ObjC) + Swift 类型元数据
# .rodata 段含 Nominal Type Descriptor → 恢复 class/struct/enum
# Hopper Disassembler — macOS 原生，Swift/ObjC 支持极佳
```

### Kotlin/Native

- 编译为原生 ELF/Mach-O（无 DEX/字节码），**无专用反编译器**
- 搜索 `Konan_` / `KRef` / `ObjHeader` 定位运行时函数
- 对象继承自 `ObjHeader`，含 `type_info` 指针 → 手动恢复对象结构
- 编译后代码膨胀严重（完整运行时库链接），`-opt` 可缩小

---

## 二十三、固件分析

### binwalk 高级用法（⭐14k）

```bash
# 递归提取固件
binwalk -Me firmware.bin

# 熵分析（识别加密/压缩区域）
binwalk -E firmware.bin

# 自定义签名提取
binwalk --magic custom.sig firmware.bin

# Python API
import binwalk
binwalk.scan('firmware.bin', signature=True, extract=True)
```

### unblob — 现代固件提取（⭐2.5k）

```bash
unblob firmware.bin  # 自动递归提取 78+ 格式
# 输出 → firmware.bin_extract/
# 含 JSON 元数据报告
```

### 固件文件系统工具

| 工具 | 格式 |
|------|------|
| **sasquatch** | 非标准 SquashFS |
| **jefferson** | JFFS2 |
| **ubi_reader** | UBI/UBIFS |
| **firmware-mod-kit** | 提取+修改+重打包路由器固件 |

### IoT 固件分析清单

```bash
# 关键文件
grep -rE "(AES|key|secret|password|token|api)" . --binary-files=text
cat etc/shadow         # 密码哈希
cat etc/rc.d/*          # 启动脚本
find . -name "*.cgi"    # CGI 程序（Ghidra 重点分析）
find /www -type f        # Web 接口
```

---

## 二十四、LLM 辅助逆向 + 2024-2026 新工具

### LLM 工具

| 工具 | 平台 | 说明 |
|------|------|------|
| **Gepetto** (⭐3.4k) | IDA Pro | 支持 OpenAI/Gemini/Ollama |
| **reverse-engineering-assistant** (⭐741) | Ghidra | MCP 服务器,LLM 直连 Ghidra |
| **binary_ninja_mcp** (⭐369) | Binary Ninja | MCP 协议集成 |
| **reverser_ai** (⭐1k) | 独立 | 本地 LLM 自动逆向 |
| **OGhidra** (⭐172) | Ghidra | Ollama 本地模型直连 |
| **LLM4Decompile** (⭐6.7k) | 独立 | 用 LLM 直接反编译二进制 |

### 2024-2026 新反编译器

| 工具 | 亮点 |
|------|------|
| **garlic** (⭐512) | 最快开源 APK/Java 反编译器（C99） |
| **pylingual** (⭐1.3k) | 现代 Python 3.8+ 字节码反编译 |
| **hyperion-disassembler** (⭐172) | 原生多架构反汇编器,支持 Lua 脚本 |
| **Ouroboros** (⭐248) | Rust 写的反编译器 |
| **arkdecompiler** (⭐185) | 纯血鸿蒙反编译器 |
| **bun-demincer** (⭐199) | Bun 编译 JS 反编译 |

### 在线服务

| 服务 | 功能 |
|------|------|
| **dogbolt.org** (⭐2.6k) | 多引擎并行对比（Ghidra/IDA/BN/angr/RetDec） |
| **RetDec** (⭐8.5k) | Avast 开源,LLVM 后端,本地部署: `retdec-decompiler input.exe` |

---

### 版本更新（2026 年）

| 工具 | 版本 | 更新要点 |
|------|------|----------|
| **Ghidra** | 12.1 | 位域恢复、ObjC 消息跟踪、Debuginfod、JDK 21 |
| **jadx** | v1.5.5 | JDK 17+、Java 反编译质量持续改进 |
| **angr** | 9.2 | 符号执行重构、Clinic 类型推导改进 |
| **IDA Pro** | 9.3 | MCP 集成、AI 辅助分析 |
| **Binary Ninja** | 5.3 | MCP 插件生态爆发 |

---

## 核心原则

1. **先 triage 再深挖**：`strings` + `file` + `binwalk` 30 秒定方向
2. **多引擎对比**：jadx + CFR 各出一份,互相对照
3. **动静结合**：静态看不懂就上 Frida/x64dbg 动态跟
4. **字符串是金矿**：搜 `http`/`secret`/`key`/`token`/`password`/加密算法名
5. **运行时 dump 是终极杀招**：任何加密/混淆最终要在内存中解密,在那一刻 dump
