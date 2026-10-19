# vowifi-go 独立实现

这是 VoHive 闭源 `github.com/iniwex5/vowifi-go` 依赖的本地替代实现，模块路径保持兼容，通过宿主 `go.mod` 的 `replace` 接入。它不是恢复的原始源码，也尚未证明与原版完整等价。

[二进制分析、附件修正和可复现证据](docs/reverse-engineering/README.md)固定于用户指定的 Linux amd64 release。下载的原版二进制没有被执行；真实 SIM、运营商网络、短信、USSD 和电话都未用于本次验证。

## 实现与边界

| 层 | 已实现 | 当前边界 |
| --- | --- | --- |
| SWu | IKE_SA_INIT、COOKIE、500→4500 NAT-T、IKE_AUTH、经典 EAP-AKA、AUTS、证书/主机名/AUTH/MAC 校验、Child SA、CP/TS、DPD、NAT keepalive | AES-CBC 128/256 + SHA1/SHA256，DH14；不支持 GCM、DH2、SHA512、AKA′、fast reauth、IKE fragmentation、MOBIKE、Child/IKE rekey |
| 数据面 | 双向 ESP、完整性、64 包 replay window、用户态 IPv4/IPv6、隧道内 TCP/UDP/DNS、SOCKS5 UDP | 不操作主机路由或 XFRM/TUN；IPv6 扩展头、分片、ESN/完整 PMTU 仍不支持 |
| IMS | REGISTER、401/407 AKA Digest、AUTS、刷新、SIP transaction、P-CSCF 选择、`ipsec-3gpp` 四组 SA | SIP UDP/TCP；内层支持 AES-CBC/null + HMAC-SHA1-96/MD5-96；认证或安全协商失败不会报告 ready |
| 短信 | GSM-7/UCS2、长短信分片/重组、RP-DATA/ACK/ERROR、SIP MESSAGE、持久化与报告关联 | SIP 2xx 仅表示接受；RP-ACK 表示 RP 提交确认，不等于收件人最终送达；完整 TP status-report 生命周期仍未实现 |
| USSI | XML、INVITE/ACK、INFO 多轮会话、BYE 取消、dialog tag 检查 | 不支持所有 multipart/运营商 XML 变体 |
| 语音 | 实际模拟呼出、18x/PRACK/200/ACK/BYE/CANCEL、迟到 2xx 清理、SDP、G.711 RTP/RTCP | 仅 PCMA/PCMU RTP/AVP；呼入通知后返回 480，尚无接听/完整双向客户端桥接、AMR、SRTP 或转码 |
| E911 | AT&T TS43 JSON/gzip action、EAP-AKA challenge、websheet 引导、可注入 HTTP | 不支持 T-Mobile entitlement；获取 websheet 不证明地址已登记，更不代表具备紧急呼叫能力 |
| 生命周期 | 宿主 API、独立就绪阶段、代次取消、逆序清理、失败清理保留重试、observer 顺序、voice agent 所有权 | 持续实网运行、真实 SIM 切换和资源压力仍需设备验收 |

SA 生命周期到期或收到暂不支持的 rekey 时会停止会话并报告错误，需要重新连接；不会继续使用过期的 SA。生产长期在线应先完成 rekey/重连的实网验收。

16 份 carrier YAML 是从目标二进制逐字节提取的历史配置，**不是 16 个已经验证互通的运营商**。配置保留原文和来源；当前引擎只能选择双方允许且自己实现的算法组合，没有可用组合时明确返回错误。例如 2degrees 的 SHA512/DH2 画像目前不能由此引擎运行。标准 AT_CHECKCODE 已按 RFC 4187 实现；`minimal/omit/checkcode` 的响应选项采用本实现的明确语义，不能据此声称已恢复原版全部 vendor 行为。设备画像生成和完整 REGISTER fallback/policy 行为仍不兼容。

SIM/APDU 与 modem 仍由 VoHive 宿主拥有。SWu 的 EAP-AKA 与 IMS 的 AKA Digest 是独立认证过程；严格 ISIM 选择会透传到宿主 provider，失败不会降级为 USIM。停止本模块不会关闭共享 modem。

## 构建和验证

使用 `go.mod` 固定的 Go 版本。单独模块测试不会自动被宿主的 `go test ./...` 包含：

```bash
cd vowifi-go
go test -race ./...
```

协议集成测试会绑定本地 loopback UDP/TCP 端口，并使用可控的 AKA/SIP/IKE peer；沙箱需要允许本地 socket。没有测试会联系运营商或使用真实 SIM。

从宿主根目录构建，先按宿主开发流程准备 `internal/web/dist`：

```bash
go test ./internal/vowifihost ./internal/sim ./internal/device ./internal/e911 ./internal/api
go build -trimpath -buildvcs=false -tags 'with_utls nomsgpack' ./cmd/vohive
```

CI 分开运行模块竞态测试、宿主集成测试和构建。Docker 在 `go mod download` 前复制本地模块，构建不再尝试下载闭源 vowifi-go。

本轮具体检查结果和环境限制记录在 [验证记录](VALIDATION.md)。
