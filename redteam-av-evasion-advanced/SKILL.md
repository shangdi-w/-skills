---
name: redteam-av-evasion-advanced
description: 红队免杀对抗高级到专家 — Process Hollowing/间接Syscall/ETW-AMSI Patching/Early Bird APC、AI免杀流水线、12款杀软针对性绕过、SilentMoonwalk/PoolParty/HWBP Unhooking调用栈欺骗、CrowdStrike/SentinelOne/MDE EDR深度对抗、Go/Rust/Nim/Zig现代Loader开发
---

# 红队免杀对抗 — 高级到专家

> 🔴 仅供授权安全测试、学术研究及教育目的使用。详见仓库 [README](../../README.md)。

## 涵盖目标

CrowdStrike Falcon · SentinelOne · Microsoft Defender for Endpoint (MDE) · Cortex XDR · Elastic EDR · Carbon Black · Cybereason

## 核心技术

SilentMoonwalk · PoolParty · HWBP Unhooking · Module Stomping v2 · Process Doppelgänging · NullGate · Voidmaw · Cronos Sleep混淆 · LLVM栈欺骗 · BYOVD · ThreadlessInject · Early Bird APC

## 文件索引

| 文件 | 内容 | 技术等级 |
|------|------|---------|
| [08-高级免杀对抗](references/08-高级免杀对抗.md) | Process Hollowing、间接Syscall、ETW/AMSI Patching、Early Bird APC | 高级 |
| [12-AI免杀技术套件](references/12-AI免杀技术套件.md) | Shellcode处理流水线 + Loader模板 + 360实战对抗 | 高级 |
| [13-杀软针对性对抗](references/13-杀软针对性对抗.md) | 12款杀软架构分析+专属绕过方案+效果排行 | 高级 |
| [14-调用栈欺骗与高级注入](references/14-调用栈欺骗与高级注入.md) | SilentMoonwalk/PoolParty/HWBP Unhooking/Module Stomping v2/Process Doppelgänging | 专家 |
| [15-EDR深度对抗](references/15-EDR深度对抗.md) | CrowdStrike/SentinelOne/MDE/Cortex XDR专属绕过+Sleep混淆+NullGate | 专家 |
| [17-现代Loader开发](references/17-现代Loader开发(Go-Rust-Nim-Zig).md) | 4种语言Loader完整模板+编译最佳实践+语言选择矩阵 | 专家 |

## 2024-2026 新技术速查

| 技术 | 简介 |
|------|------|
| **SilentMoonwalk** | 栈欺骗标杆，Desync模式绕过所有EDR → [14](references/14-调用栈欺骗与高级注入.md) |
| **PoolParty** | 8种线程池注入变体，无CreateThread → [14](references/14-调用栈欺骗与高级注入.md) |
| **HWBP Unhooking** | 硬件断点绕过AMSI/ETW，零内存修改 → [14](references/14-调用栈欺骗与高级注入.md) |
| **NullGate** | Defender NtCreateThreadEx扫描时序绕过 → [15](references/15-EDR深度对抗.md) |
| **Voidmaw** | INT3屏蔽执行，每次仅1条指令可见 → [15](references/15-EDR深度对抗.md) |
| **Cronos** | 可等待定时器Sleep混淆 → [15](references/15-EDR深度对抗.md) |
| **LLVM栈欺骗** | 编译时自动注入，无需改源码 → [14](references/14-调用栈欺骗与高级注入.md) |
| **Go/Rust/Nim/Zig** | 新一代Loader语言，杀软训练集盲区 → [17](references/17-现代Loader开发(Go-Rust-Nim-Zig).md) |

## 快速查找

| 场景 | 看哪里 |
|------|--------|
| 过360核晶 | 08 + 12 + 17 |
| 过 CrowdStrike | 14 + 15 |
| 过 SentinelOne | 15 + 17（Go/Rust） |
| 过 Defender (MDE) | 13 + 15（NullGate/Voidmaw） |
| 调用栈欺骗 | 14 |
| EDR 专属对抗 | 15 |
| AI 辅助免杀 | 12 |
| Go/Rust/Nim/Zig Loader | 17 |
| 进程注入新法 | 14（PoolParty 8变体 / ThreadlessInject） |
| Sleep 混淆 | 15（Cronos/定时器混淆） |
| BYOVD/驱动 | 见基础 skill 07/16 |

## 推荐学习路径

```
高级:   08 → 12 → 13 → 17
专家:   14 → 15（EDR深度对抗）
```
