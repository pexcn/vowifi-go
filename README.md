# vowifi-go 独立实现

这是 VoHive 闭源 `github.com/iniwex5/vowifi-go` 依赖的独立替代实现，从 `pexcn/vohive` 的 `rea` 分支提取，并保留模块相关提交历史。它不是恢复的原始源码，也尚未证明与原版完整等价。

本仓库提供 Go 库，入口为 `runtimehost`；SIM/APDU 和 modem 由宿主通过接口注入，不依赖 VoHive 源码或 Web 前端。

[二进制分析、附件修正和可复现证据](docs/reverse-engineering/README.md)固定于用户指定的 Linux amd64 release。下载的原版二进制没有被执行；真实 SIM、运营商网络、短信、USSD 和电话都未用于本次验证。

## 实现与边界

| 层 | 已实现 | 当前边界 |
| --- | --- | --- |
| SWu | IKE_SA_INIT、COOKIE、INVALID_KE_PAYLOAD、500→4500 NAT-T、IKE_AUTH、经典 EAP-AKA、AUTS、证书/主机名/AUTH/MAC 校验、Child SA、CP/TS、DPD、NAT keepalive | AES-CBC 128/256 + SHA1/SHA256，默认 DH14、配置明确提出时支持 DH2；不支持 GCM、SHA512、AKA′、fast reauth、IKE fragmentation、MOBIKE、Child/IKE rekey |
| 数据面 | 双向 ESP、完整性、64 包 replay window、用户态 IPv4/IPv6、隧道内 TCP/UDP/DNS、SOCKS5 UDP | 不操作主机路由或 XFRM/TUN；IPv6 扩展头、分片、ESN/完整 PMTU 仍不支持 |
| IMS | REGISTER、401/407 AKA Digest、AUTS、刷新、SIP transaction、P-CSCF 选择、`ipsec-3gpp` 四组 SA | SIP UDP/TCP；内层支持 AES-CBC/null + HMAC-SHA1-96/MD5-96；认证或安全协商失败不会报告 ready |
| 短信 | GSM-7/UCS2、长短信分片/重组、RP-DATA/ACK/ERROR、SIP MESSAGE、持久化与报告关联 | SIP 2xx 仅表示接受；RP-ACK 表示 RP 提交确认，不等于收件人最终送达；完整 TP status-report 生命周期仍未实现 |
| USSI | XML、INVITE/ACK、INFO 多轮会话、BYE 取消、dialog tag 检查 | 不支持所有 multipart/运营商 XML 变体 |
| 语音 | 实际模拟呼出、18x/PRACK/200/ACK/BYE/CANCEL、迟到 2xx 清理、SDP、G.711 RTP/RTCP | 仅 PCMA/PCMU RTP/AVP；呼入通知后返回 480，尚无接听/完整双向客户端桥接、AMR、SRTP 或转码 |
| E911 | AT&T TS43 JSON/gzip action、EAP-AKA challenge、websheet 引导、可注入 HTTP | 不支持 T-Mobile entitlement；获取 websheet 不证明地址已登记，更不代表具备紧急呼叫能力 |
| 生命周期 | 宿主 API、独立就绪阶段、代次取消、逆序清理、失败清理保留重试、observer 顺序、voice agent 所有权 | 持续实网运行、真实 SIM 切换和资源压力仍需设备验收 |

SA 生命周期到期或收到暂不支持的 rekey 时会停止会话并报告错误，需要重新连接；不会继续使用过期的 SA。生产长期在线应先完成 rekey/重连的实网验收。

宿主默认通过 RFC 5998 的 `EAP_ONLY_AUTHENTICATION` 通知协商 EAP-only：首轮可以没有证书 AUTH，经过 EAP-AKA 的 AUTN/AT_MAC、EAP Success 和最终 MSK AUTH 验证后才建立 Child SA。如果对端仍发送证书 AUTH，必须正常验证，不会在证书或签名错误后回退。直接使用 SWu 引擎的调用者需显式设置 `Config.EAPOnlyAuthentication`；关闭时保留证书优先流程。见 [首轮 EAP-only 修复说明](docs/reverse-engineering/eap-only-authentication.md)。

原版在完成经典 mutual EAP-AKA 并持有 MSK 等条件下有受限的缺失 responder AUTH 兼容分支；本实现仍按 RFC 5998 要求最终 MSK AUTH。这个认证策略差异可能影响部分 ePDG 的互通，不能把本实现的行为等同于已复刻原版全部兼容分支。

CP 接收端按 RFC 7296 忽略保留字段，并在完整标准 TLV 解析失败时尝试原版支持的 TV 短属性编码。错误配置类型、截断报文和没有有效本地地址仍会失败，见 [CFG_REPLY 兼容与诊断说明](docs/reverse-engineering/cp-configuration-compatibility.md)。

宿主启用 `Config.EPDGFailover`：仅在首轮 IKE_SA_INIT 没有收到任何可交付的 datagram 时，优先尝试其他已解析 ePDG 地址的原配置端口，再尝试 UDP 4500，最多八个地址/端口组合；备用组合最多发送三次初始请求。每次重新生成 SPI、DH 和 nonce，保留原始认证主机名及全部认证校验。收到错误通知、COOKIE 后超时、解析错误或认证失败均不触发该地址回退；自定义传输和非标准端口也不自动回退。超时诊断包含 endpoint 和全部解析 IP。运营商 `dns_server` 配置会透传给 ePDG 解析器，留空仍使用系统解析器。

宿主会保留运营商配置中本引擎支持、且有匹配 ESP 参数的 IKE 提议，默认提议优先。仅允许服务器选择其中一组；收到 `INVALID_KE_PAYLOAD` 时，只能向已提出的 DH 组重新发起一次握手。DH2（MODP_1024）/SHA1 用于 Vodafone UK 原版日志所示的兼容组合，不会在未配置的情况下自动添加，见 [Vodafone UK 对照说明](docs/reverse-engineering/vodafone-uk-negotiation.md)。

16 份 carrier YAML 是从目标二进制逐字节提取的历史配置，**不是 16 个已经验证互通的运营商**。配置保留原文和来源；当前引擎只能选择双方允许且自己实现的算法组合，没有可用组合时明确返回错误。例如 2degrees 的 SHA512/DH2 画像目前不能由此引擎运行。标准 AT_CHECKCODE 已按 RFC 4187 实现；`minimal/omit/checkcode` 的响应选项采用本实现的明确语义，不能据此声称已恢复原版全部 vendor 行为。设备画像生成和完整 REGISTER fallback/policy 行为仍不兼容。

SIM/APDU 与 modem 仍由 VoHive 宿主拥有。SWu 的 EAP-AKA 与 IMS 的 AKA Digest 是独立认证过程；严格 ISIM 选择会透传到宿主 provider，失败不会降级为 USIM。停止本模块不会关闭共享 modem。

## 作为 Go 模块使用

```bash
go get github.com/pexcn/vowifi-go@v0.1.0
```

宿主使用 `github.com/pexcn/vowifi-go/runtimehost` 等包。迁移原版兼容路径时，需要同步更新 Go import 和 `go.mod`；不应在同一进程同时引入两个路径下的模块。

## 使用和验证

使用 `go.mod` 固定的 Go 版本，在本仓库根目录操作：

```bash
go test ./...
go vet ./...
```

协议集成测试会绑定本地 loopback UDP/TCP 端口，并使用可控的 AKA/SIP/IKE peer；运行环境需要允许本地 socket。没有测试会联系运营商或使用真实 SIM。CI 独立检查本模块。

宿主通过 `runtimehost` 提供的请求、SIM provider、存储和观察者接口接入。VoHive 的设备管理、Web/API 和 modem 后端留在宿主仓库，部署时仍由 VoHive 提供完整应用。

开发时可在 VoHive 根目录使用本地替换：

```bash
go mod edit -replace=github.com/pexcn/vowifi-go=../vowifi-go
```

此命令假定两个仓库位于同级目录；发布接入应固定新仓库的 tag 或提交版本。

拆分前的检查结果和环境限制保留在 [历史验证记录](VALIDATION.md)。本仓库保留来源仓库的 [许可证](LICENSE)，提取来源见 [NOTICE](NOTICE)。
