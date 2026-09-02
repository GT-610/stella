# ADR 0029：通过显式 HTTP 代理建立 Secure WebSocket 隧道

- 状态：已由 ADR 0030 取代
- 日期：2026-09-02

## 背景

Secure WebSocket Relay 的目标环境包含只能通过显式代理访问 HTTPS 的校园网和企业网。
首个实现只会直接连接 Relay，因此即使代理允许 WebSocket，代理限定网络中的客户端仍然
无法使用这一兜底承载。

代理是客户端所在网络的本地路由设置。由控制器下发会泄露无助于其他节点的本地信息，
也可能把一个地点的代理错误应用到另一个地点。

## 决策

Windows 客户端配置可以包含一个可选的数值 `secure_websocket_proxy` 套接字地址。它只
影响 Secure WebSocket；直连 UDP、TURN UDP、TURN TCP 和 TURN TLS 保持原有行为与
回退顺序。

启用后，客户端先连接代理，再发送一条 HTTP/1.1 `CONNECT`。请求目标和 `Host` 都是
规范的 Relay WebSocket authority。CONNECT 不携带 Stella Relay 凭据或代理凭据。首个
参考实现不持久化或自动生成代理认证材料，`407` 与其他非成功响应一样失败关闭。

响应头受正常连接期限约束，上限 16 KiB 和 64 个字段；只接受完整的 HTTP/1.0 或
HTTP/1.1 2xx 响应。畸形字段、折行、临时响应、重定向、认证挑战、响应正文或头部后的
额外字节均被拒绝，日志不记录响应字段值。

CONNECT 成功后，客户端才在隧道内执行 TLS 1.3，并按直连时相同的 Relay 名称、Web PKI
和 SPKI pin 规则验证对端。TLS 成功后才发送带 Relay 身份认证的 WebSocket 升级，因此
代理不会看到明文 TURN 凭据或 Stella 数据报。

## 影响

无需认证的显式 HTTP 代理可以通过普通 HTTPS 所用的出站 TCP 443 策略承载 Stella。
代理仍能观察 Relay authority、客户端地址、时序和流量大小，但无法在不破坏 TLS 校验的
情况下读取或修改 Relay 与二层内容。

需要 Basic、Digest、NTLM、Kerberos 或交互认证的代理暂不支持。未来接入操作系统凭据
会改变秘密存储、界面和模拟身份边界，需要另行作出架构决策。
