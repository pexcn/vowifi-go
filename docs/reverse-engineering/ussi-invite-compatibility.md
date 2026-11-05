# USSI 初始请求兼容性

用户反馈德国 Vodafone 经 VoWiFi 发送 `*100#` 时收到 `SIP/2.0 400 Bad Request`，同一业务记得在原版可用。此处记录原版静态证据与修复边界，不把本地模拟结果当作运营商验证。

## 原版依据

目标为用户指定的 [VoHive v1.5.5-10u Linux amd64](https://github.com/pexcn/docker-images/releases/download/vohive/vohive_v1.5.5-10u_linux_amd64)，SHA-256 为 `2b080980c72fede3dbad1c9f8830bb51d0bc368b4acb576c4f2d27f9182eb59f`。没有执行该文件或发送真实 SIM/运营商请求。

REA/Ghidra 返回的完整记录见 [Evidence bundle](evidence/ussi-rea-bundle.json)。Go 函数元数据与同一 ELF 的地址/字符串长度用于核对伪代码中的 DAT 引用；导出值见 [wire observations](evidence/ussi-wire-observations.json)。

| 函数 | 地址 | REA Evidence ID | 已核对的行为 |
| --- | --- | --- | --- |
| BuildInitialInvite | `0x1094b00` | `ev_181aa9411175137cbe18fa0bb884f2713c5cbac48d0f66d8ebb4e2bb7bbdd3ef` | 调用 dialstring、multipart、Profile 构造逻辑 |
| BuildMultipartBody | `0x1097360` | `ev_433ab731e6e45a8e317f2339ebfa23cfaac5ce04b8e046401a23a9a9f7cc082a` | `vohive_ussd` 边界、SDP + XML、render disposition |
| BuildSDP | `0x1097a80` | `ev_a95879942c2f6feed768995bdc72a2bd6c59a53b3109475bc2b185d8d3445d4e` | 本地 IPv4/IPv6、音频端口 0、固定能力描述 |
| Profile.ApplyInitialInvite | `0x1099100` | `ev_b3e4969797103398b299b8caa6197ee340693d7be92bf6ff5abb9061c3048b28` | 根据 Profile 设置 IMS 服务头 |
| dialstringURI | `0x1095f20` | `ev_4df86f2d1ff9df244bd817dfb0529bdee37c2f1d87eedd2d3d461d288d01cb8d` | 保留 `*`、将 `#` 转成 `%23`、phone-context、user=dialstring |
| EncodeXML | `0x109e280` | `ev_cb05fa525c4f5ff462792f79601643444b6d63f33d1a1cfe165cceb2256ea5d1` | UTF-8 XML declaration、媒体类型字符串作为 xmlns |
| ExtractFromMultipart / responseCarriesUSSD | `0x1097140` / `0x109d400` | 见 bundle | 从 multipart 响应中取得 USSD 内容 |

Ghidra 12.1.4 不支持原版 Go 1.26.3 的自动类型恢复；本次按 Go 元数据地址查询，并跳过 `Decompiler Switch Analysis`、`Stack`、`Reference` 自动分析器。类型、参数和全程序调用覆盖不视为完整。所有会话已导出并关闭。

## 实现

- 初始 INVITE 使用公共身份中的 IMS 域作为目标与 phone-context（无域时回退到配置 Realm），保留星号并编码用户输入的 URI 分隔符。请求使用 SDP + XML multipart，SDP 音频端口为 0，不开启媒体流。
- 恢复 MMTEL 服务选择、首选身份、Recv-Info，复用注册的 Contact、路由、PANI 与 Security-Verify。只有已协商 security agreement 时添加 sec-agree。消息体完成后才计算 Digest 和 Content-Length。
- XML 显式输出原版 xmlns；接收端同时接受原版、URI namespace 和无 namespace。原有代码为 XMLName 设置 Space 的写法实际上没有输出 xmlns，线格式测试已覆盖这一点。
- 内容解析统一处理直接 XML、legacy media type 与声明边界的 multipart/mixed；拒绝坏 MIME、重复 XML、错误 namespace 和超限内容。SDP-only 200 等待后续 INFO，空 ussd-string 则作为有效结果返回。
- 在响应分发时学习确认后的 dialog 身份、Contact 与路由，再唤醒发送方。这样同一 TCP 批次中的 200 + 菜单 INFO 不依赖 goroutine 调度先后。错误响应、无效初始结果与 flow 失效清理本地会话。

原版的所有能力声明没有原样复制。USSI 当前不处理可靠临时响应/PRACK，也不支持视频、SRVCC 或网络主动发起的 USSI；保留现有 Contact 中已实现的能力，不额外宣告这些功能。没有添加 Vodafone 专属分支、失败后自动重新提交 USSD 或 CS 回退。

## 验证边界

本地测试验证实际序列化的 URI、服务头、IPv4/IPv6 SDP、XML、MIME 边界、Content-Length 和覆盖完整 multipart body 的 auth-int。loopback 验证直接 XML 与 multipart 首轮、多轮回复、SDP 确认后立即到达的菜单、BYE 结果、取消、坏菜单拒绝与失败清理，并回归 flow 恢复。

这些证据确认修复了协议差异，但没有证明 400 具体由哪一个字段引起。仍需用德国 Vodafone 实卡验证 `*100#` 首轮和菜单回复；若继续拒绝，应比较原版/新版请求与完整 SIP 响应诊断字段。
