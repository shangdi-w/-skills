---
name: redteam-av-evasion
description: 红队免杀对抗基础到中级 — 杀软检测原理、7种免杀技术分类、25+工具详解、C/C++/C#/Python/PowerShell Shellcode加载、113+ LOLBins白名单利用、渗透脚本免杀、综合策略、实战SOP、持久化与提权对抗
---

# 红队免杀对抗 — 基础到中级

> 🔴 仅供授权安全测试、学术研究及教育目的使用。详见仓库 [README](../../README.md)。

## 涵盖目标

Windows Defender · 360核晶 · 火绒 · 卡巴斯基 · ESET · McAfee · Sophos · Bitdefender · Avast · AVG

## 文件索引

| 文件 | 内容 | 技术等级 |
|------|------|---------|
| [01-免杀基础知识](references/01-免杀基础知识.md) | 杀软检测方式、7种免杀技术分类、msfvenom全参数 | 入门 |
| [02-免杀工具篇](references/02-免杀工具篇.md) | 25+款工具详解+效果排行+9种MSF免杀方式 | 入门 |
| [03-Shellcode加载-C-CPP](references/03-Shellcode加载-C-CPP.md) | C/C++ 10种加载方法 + VT查杀率 | 初级 |
| [04-Shellcode加载-CSharp](references/04-Shellcode加载-CSharp.md) | C# 5种加载方法（含D/Invoke+间接syscall） | 初级 |
| [05-Shellcode加载-Python](references/05-Shellcode加载-Python.md) | Python 8种加载方法 + PyInstaller | 初级 |
| [06-Shellcode加载-PowerShell](references/06-Shellcode加载-PowerShell.md) | PowerShell 4种加载方法 + AMSI绕过 | 初级 |
| [07-LOLBins白名单利用](references/07-LOLBins白名单利用.md) | 113+个白名单程序 + 6大类分类 + 5条实战利用链 | 中级 |
| [09-综合免杀策略](references/09-综合免杀策略.md) | 18条核心实战思路 + 策略组合矩阵 | 中级 |
| [10-免杀实战SOP](references/10-免杀实战SOP.md) | 完整操作流程：生成→加载→验证上线 | 实战 |
| [11-渗透脚本免杀](references/11-渗透脚本免杀.md) | PS/VBA/HTA/JScript全脚本免杀+macro_pack+EvilClippy | 中级 |
| [16-持久化与提权对抗](references/16-持久化与提权对抗.md) | 免杀持久化+UAC绕过Win11+BYOVD+DLL侧加载+令牌窃取 | 高级 |

## 快速查找

| 场景 | 看哪里 |
|------|--------|
| 新手入门 | 01 → 02 → 10 |
| 选工具 | 02-免杀工具篇 |
| 需要 Loader 代码 | 按语言：03(C/C++) / 04(C#) / 05(Python) / 06(PS) |
| 过 Defender | 07 + 09 + 13(见 advanced skill) |
| 过火绒 | 07 + 13(见 advanced skill) |
| 无文件攻击 | 07 + 11 |
| 持久化免杀 | 16 |
| 完整流程 | 10 |

## 推荐学习路径

```
入门:   01 → 02 → 10（实战SOP）
初级:   03/04/05/06（按语言选Loader）
中级:   07 → 09 → 11 → 16
```
