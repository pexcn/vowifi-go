# 首轮 EAP-only 认证兼容修复

用户在 CTEUK（234/33）启动测试中遇到 `SWu: responder certificate AUTH required before EAP`。日志表明 IKE_AUTH 已收到对端响应，但旧实现要求先取得证书 AUTH，无法进入没有首轮 AUTH 的 EAP 流程。该日志本身不包含报文，不能证明后续鉴权或 IMS 注册能否完成；本次没有访问用户的真实 SIM、NAS 或运营商网络。

此次依据 [RFC 5998 第 3 节](https://www.rfc-editor.org/rfc/rfc5998.html#section-3) 补齐标准协商：

1. 宿主生成的 SWu 配置启用 EAP-only。在首个 IKE_AUTH 请求内发送通知 16417，Protocol ID、SPI size 为 0，无通知数据。
2. 对端首轮没有 AUTH 时允许继续 EAP Identity / 经典 EAP-AKA，保留首轮 IDr。对端身份缺失、重复或中途改变会失败。
3. 只有完整互认证并取得 MSK 后才能发送客户端 AUTH；最终服务端 AUTH 必须使用 MSK，校验覆盖 IKE_SA_INIT transcript、nonce、IDr。没有最终 AUTH、错误 MSK proof 或使用证书代替最终 MSK proof 都会失败，Child SA 不会提前建立。
4. 对端若忽略 EAP-only 通知并发送证书 AUTH，照常验证证书链、主机名和签名；失败不会切换为无证书流程。

这与原版的“完成 EAP 后允许缺失额外 responder AUTH”分支是两个不同问题。RFC 5998 明确要求 EAP Success 后的双向 AUTH 使用 EAP 生成的密钥；本次没有放宽最终 MSK proof。

离线回归使用 loopback UDP 的 IKE/EAP peer，覆盖直接 AKA challenge、先 Identity 再 challenge、证书流程兼容及 Child SA 的实际 ESP 发包。拒绝测试覆盖坏 AT_MAC、过早 EAP Success、不支持的 EAP 方法、缺失/重复/变化 IDr、缺失/伪造最终 AUTH、最终证书 AUTH，以及启用 EAP-only 时仍拒绝无效证书/签名。测试使用合成身份，不保存用户日志中的真实 IMSI、ICCID、IMEI 或密钥。
