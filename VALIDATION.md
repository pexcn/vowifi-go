# 本轮验证记录

日期：2026-10-19。仓库基点：`07b7b8691a2bb50db907219bcc7d7ae7f0263f65`，分支 `rea`。使用 Go 1.26.3、Linux amd64；交叉构建目标为 Linux amd64/arm64。默认宿主测试/构建使用 `CGO_ENABLED=0`，竞态测试显式设置为 `1`。协议集成测试需要本地 UDP/TCP socket 权限。

## 检查结果

| 检查 | 结果 / 范围 |
| --- | --- |
| 子模块 `CGO_ENABLED=1 go test -race -count=1 ./...` | 通过；包含全部协议、网络、业务和生命周期包 |
| 宿主 `CGO_ENABLED=0 go test -p=1 -count=1 ./...` | 通过；未排除任何测试 |
| 宿主 `CGO_ENABLED=1 go test -race -count=1 ./internal/db` | 通过；包含分片持久化与聚合回归 |
| 子模块 `go vet ./...` | 通过；首次发现一个语音测试的未命名结构体字段，修正后通过，并重新运行 IMS 竞态测试 |
| 宿主 `go vet ./...` | 通过 |
| Linux amd64 构建 | 通过，`CGO_ENABLED=0` |
| Linux arm64 交叉构建 | 通过，`CGO_ENABLED=0` |
| IKE 编解码 fuzz | 3 秒、152,013 次执行，通过 |
| EAP 解析 fuzz | 3 秒、43,896 次执行，通过 |
| 宿主定向竞态检查 | `internal/vowifihost`、`internal/e911`、`internal/device` 的启动失败清理、HTTP adapter 和 VoWiFi/runtime 用例通过 |

构建命令从宿主根目录执行；本轮已准备宿主的 `internal/web/dist` 嵌入资源：

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -buildvcs=false -tags 'with_utls nomsgpack' -o work/vohive-amd64 ./cmd/vohive
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -buildvcs=false -tags 'with_utls nomsgpack' -o work/vohive-arm64 ./cmd/vohive
```

机器可读的实际命令、退出码和耗时保存于 [verification.json](docs/reverse-engineering/evidence/verification.json)。记录保留首次失败和修复后的复查，不把失败尝试删除为全绿历史。

早期宿主测试单独排除了写死 `/root/.gemini/antigravity/vohive.db` 的旧 `TestCheckSchema`；随后已将该测试修为使用临时数据库并检查实际迁移的分片表，完整重跑全部宿主测试通过。使用 `-p=1` 避免大量并行编译令原有的短时 APDU watchdog 测试受到调度干扰；没有修改 watchdog 阈值。

前两次 GitHub CI 的协议竞态与 vet 通过，但宿主 job 均失败于原有 `TestAddWorkerQMIManagedRebindsByIMEIWhenControlDeviceGone`，见 [首次 CI](https://github.com/pexcn/vohive/actions/runs/39193528271) 和 [第二次 CI](https://github.com/pexcn/vohive/actions/runs/39194011592)。最初将差异归因于 CGO 的判断不成立：启用/禁用 CGO 都会发生。根因是该用例断言虚构设备初始化必须失败，却使用系统默认的 `qmi-proxy`，受宿主环境影响。用例现显式选择临时目录下不存在的 proxy/socket，不接触系统代理，并检查确实走过 IMEI 重发现进入 QMI startup 失败阶段。隔离后的用例连续 3 次竞态运行通过。宿主 CI 保持 `CGO_ENABLED=0` 以匹配发布构建；没有删除或跳过该测试。

## 测试所覆盖的行为

- SWu 使用真实 loopback UDP peer，覆盖 COOKIE、同一 socket 切换至 NAT-T、证书/AUTH、AKA、AUTS、AT_CHECKCODE、Child SA、ESP、DPD、NAT keepalive、IPv4/IPv6 请求和 SOCKS5 UDP。500/4500 通过随机端口映射模拟，避免占用特权端口；同时检查客户端请求的 NAT-T 端口确为 4500。无效 MAC/AUTH、超时和暂不支持的 rekey 会失败并关闭会话。
- 密码实现使用已发布的 HMAC/AES-CBC 向量，检查 DH 子群和非法输入。ESP 校验包括损坏报文、重放和完整性失败后不能污染接收窗口。
- 用户态网络测试覆盖隧道内 TCP/UDP/DNS，以及 IMS 四组 SA 的受保护 TCP/UDP 数据。IMS 受保护服务端端口可接收网络发起的短信，并从收到请求的端口/连接回复；错误来源和缺失 listener 被拒绝。
- IMS 覆盖认证、注册刷新、SIP 报文、长短信、RP-ACK/ERROR、重组/去重、USSI dialog，以及呼出的可靠临时响应、RTP/RTCP、取消和迟到成功响应清理。
- 生命周期覆盖过期设备代次取消、逆序清理、失败清理保留重试、observer 重入/停止、语音 gateway 所有权。严格 ISIM 不回退 USIM，JSON 字段与宿主前端契约一致。
- 短信持久化覆盖现有非唯一索引下的分片更新，以及长短信首片提前 ACK 时不能把整条短信判为已确认。E911 使用注入的 HTTP/AKA fixtures，不访问运营商服务。

## 解释结果时的限制

这些测试在受控 peer 上验证了独立实现；没有执行下载的原版二进制，没有使用真实 SIM，没有联系运营商，也没有发送真实短信、USSD 或电话。尚未建立真实网络互通或原版完整等价的证据。

arm64 是编译验证，没有在 arm64 设备运行。Dockerfile 已接入本地模块，但本轮没有构建 Docker 镜像。短时 fuzz 不能替代持续模糊测试或审计。当前缺少 rekey/MOBIKE、部分算法及语音接听/完整客户端桥接，详见 [实现范围](README.md)。真实设备验收仍须核对运营商协商、证书链、入站业务、切卡、重连和长期资源使用。

## 首轮 EAP-only 修复复查

收到 CTEUK（234/33）的启动失败日志后，补齐 RFC 5998 协商和首轮无证书 AUTH 的认证流程。复查结果：模块全量竞态测试、模块 `go vet`、宿主 `internal/vowifihost` / `internal/sim` / `internal/device` / `internal/e911` / `internal/api` 测试，以及 Linux amd64/arm64 构建全部通过，见 [实际命令与结果](docs/reverse-engineering/evidence/eap-only-verification.json)。新增 `TestEAPOnly*` 用例另以 `CGO_ENABLED=1 go test -race -count=3 ./engine/swu -run TestEAPOnly` 连续运行通过，覆盖双向 ESP 和认证拒绝场景。没有重新连接用户的 SIM/ePDG，不据此宣称实网已恢复。协议依据与边界见 [修复说明](docs/reverse-engineering/eap-only-authentication.md)。

## CFG_REPLY 解析修复复查

随后收到的 `expected CFG_REPLY` 表明流程已到达 Child SA 配置解析；该错误原先混合了格式错误和类型不符，日志本身没有足够信息确定实际 CP 编码。按照 RFC 7296 的保留字段接收规则及指定原版的局部静态反汇编，补齐保留字段处理、完整 TLV 优先的 TV 兼容解析及错误诊断，详见 [兼容说明](docs/reverse-engineering/cp-configuration-compatibility.md)。

模块全量竞态测试、模块 `go vet`、上述五个宿主包测试及 Linux amd64/arm64 构建全部通过。IKE 编解码 fuzz 运行 3 秒、73,434 次执行，通过；机器可读结果见 [cp-verification.json](docs/reverse-engineering/evidence/cp-verification.json)。新增固定 wire 向量与完整 EAP-only/双向 ESP 回归覆盖兼容报文，并检查错误类型、截断、错误地址长度及没有地址时拒绝建立会话且关闭传输。这些验证均使用本地受控 peer，仍需用户设备实测确认。
