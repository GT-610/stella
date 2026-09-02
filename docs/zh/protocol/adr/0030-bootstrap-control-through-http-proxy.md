# ADR 0030：通过本地 HTTP 代理引导控制器 TLS

- 状态：已接受
- 日期：2026-09-02
- 取代：ADR 0029 中仅限 WSS 的配置范围

## 背景

ADR 0029 允许 Secure WebSocket Relay 通过显式 HTTP 代理，但客户端必须先认证控制器，
取得 Relay 服务记录和短期凭据后才能使用它。现有控制器连接仍是直连 TCP，因此代理-only
网络会在发现和授权 WSS 兜底之前失败。

为控制面和 Relay 设置两个代理很容易造成只有引导或只有数据兜底可用。两者都是到运营者
authority 的出站 TLS，应共享同一套本地出口策略。

## 决策

Windows 客户端使用一个可选的数值 `https_proxy` 套接字地址，同时服务于控制器 TLS 和
Secure WebSocket Relay。它取代 ADR 0029 引入的 `secure_websocket_proxy` 字段。该设置
只存在本地，不发送给控制器，也不影响直连 UDP、TURN UDP、TURN TCP 或直连 TURN TLS。

控制器 TLS 前，客户端先连接代理，再按 WSS Relay 相同的严格有界 HTTP/1.1 CONNECT
方案建立隧道。目标和 Host 是控制器 TLS 名称加控制器端口。明文请求不包含注册令牌、加入
令牌、节点或控制器证明、SPKI pin 及任何 Stella 记录；包括 407 在内的非 2xx 响应都会
失败关闭。

CONNECT 成功后，原有 TLS 1.3、名称与 SPKI 校验、TLS exporter 绑定和双向 Stella 身份
证明在隧道内保持不变。控制器和 WSS 共用同一个 CONNECT 实现和限制，避免解析器与日志
行为分叉。

## 影响

无需认证的代理-only 网络中的客户端可以完成控制器认证、接收连接配置、建立 WSS Relay
分配并加入二层覆盖网络，无需直连 TCP 路由或端口映射。代理能观察目标 authority、时序和
字节量，但控制器和 Relay 的凭据及内容仍由端到端 TLS 保护。

需要认证的代理方案仍不在首个方案内。未来应设计操作系统凭据和模拟身份边界，而不是把
可复用代理密码写入 Stella TOML。
