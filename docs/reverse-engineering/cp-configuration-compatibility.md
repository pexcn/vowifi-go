# CFG_REPLY 配置解析兼容与诊断

用户在 CTEUK（234/33）收到 `SWu: expected CFG_REPLY`。按该版本的调用顺序，这表示 EAP、最终 responder AUTH、Child SA proposal 和 Traffic Selectors 已通过相应校验，随后在 Configuration Payload 处理处失败。旧代码把 `ParseCP` 的格式错误与 `cfg_type != 2` 合并为同一条错误。现有日志没有 CP 内容，**不能据此确定用户收到的是哪种格式，也不能据此宣称实网已恢复**。

## 规范与原版观察

[RFC 7296 §3.15](https://www.rfc-editor.org/rfc/rfc7296.html#section-3.15) 要求 CP 头的三个保留字节在发送时为零、接收时忽略。[§3.15.1](https://www.rfc-editor.org/rfc/rfc7296.html#section-3.15.1) 对属性最高位 R 也作同样要求，属性类型占低 15 位。重写版原先直接拒绝这两处非零保留字段，不符合接收规则。

指定原版 artifact SHA-256 仍为 `2b080980c72fede3dbad1c9f8830bb51d0bc368b4acb576c4f2d27f9182eb59f`。Go 函数表定位 `ikev2.DecodePayloadCP` 于 `0xfa05a0`，`ikev2.decodeCPAttribute` 于 `0xfa0780`。本地 GNU objdump 的[局部反汇编](evidence/cp-original-decode.asm)显示：前者跳过四字节 CP 头再遍历属性；后者将类型与 `0x7fff` 相与，并在高位设置时复制两字节 inline value、消耗四字节，否则读取 TLV length。该兼容路径采用 IKEv1 风格的 TV 短属性编码，**不是 RFC 7296 定义的 CP 格式**。这些是本地静态指令观察，不是新增 REA Evidence 或原始源码。

## 本次改动

- 优先按完整的标准 TLV 报文解析，同时忽略保留字段。仅在完整 TLV 解析失败时，尝试与原版相同的 TV 短属性解释；只有整个备用解析成功才返回，不返回部分属性。不会将所有高位属性直接当成 TV，避免破坏合法的“R 位非零但仍为 TLV”的报文。
- 发出的属性仍为标准 TLV，编码器拒绝超出 15 位的类型。
- 空的地址/DNS/P-CSCF 属性视为未提供值；仍须至少取得一个有效、属于协商 TS 范围的本地地址才会建立 Child SA。错误长度、地址族、未指定/多播地址等校验保留。
- 将“CP 缺失或重复”“格式错误”“CFG type 错误”“已知属性值长度错误”拆分。错误包含类型、长度、偏移和剩余字节数，不输出地址原文、认证密钥或用户身份。

完整报文优先策略不承诺恢复所有混合或歧义厂商编码。错误 CFG type（例如 CFG_SET=3）仍会被拒绝，截断报文、缺失本地地址也不会被放行。

## 回归

固定十六进制向量覆盖标准 TLV、非零 CP 保留字节、属性 R 位、TV 短属性、标准 TLV 优先、空属性及截断错误。完整 loopback UDP / EAP-only 握手覆盖上述兼容变体，检查分配的地址、DNS、P-CSCF，并实际收发 ESP。拒绝测试覆盖错误 CFG type、截断长度、无效地址长度和没有地址，均须关闭传输而非报告成功。测试不使用用户日志中的真实身份。
