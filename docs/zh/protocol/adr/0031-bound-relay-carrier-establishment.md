# ADR 0031：限制 Relay carrier 建立时间

- 状态：已接受
- 日期：2026-09-02

## 背景

ADR 0025 要求客户端在进行直连 ICE 探测时维持待命 Relay。Windows 客户端依次尝试
TURN UDP、TCP、TLS 和 Secure WebSocket。TURN 事务和 HTTP CONNECT 已有期限，但
操作系统 TCP 连接、TLS 握手、WebSocket 升级以及完整的多阶段分配此前没有共享的外层
期限。

严格防火墙可能静默丢弃较早的 carrier，而不是立即拒绝连接。客户端因此可能等到操作
系统超时后才能尝试网络实际允许的 carrier。如果给每个 Relay 地址各自设置独立期限，
总延迟仍会随控制器下发的 Relay 服务及 IPv4、IPv6 地址数量增长。

## 决策

Windows 客户端按 TURN UDP、TURN TCP、TURN TLS、Secure WebSocket 的优先顺序，
为每种 Relay carrier 设置一个共享的 10 秒单调时钟建立预算。同一 carrier 下的全部
Relay 服务和地址共享该预算；预算覆盖套接字连接、适用时的 HTTP CONNECT、TLS、
WebSocket 升级、TURN 认证与分配等完整过程。

某次尝试立即失败时，只要当前 carrier 仍有剩余预算，就可以继续尝试其他服务或地址。
预算耗尽时取消正在进行的尝试，跳过该 carrier 的剩余候选，并继续下一种 carrier。记录
的错误只包含 Relay ID 和 carrier，不包含凭据、代理响应、主机名、证书或数据包内容。
已有的更细粒度事务期限继续作为纵深限制。

Relay 主机名解析仍是独立的有界准备步骤。任一分配成功即结束回退；如果所有候选都失败
或超时，启动返回最后一个安全的分配错误，不会在控制器要求 Relay 时静默地无 Relay
运行。

## 影响

静默阻断 UDP、原始 TCP 或直连 TLS 的网络不能无限期阻止客户端尝试兼容 HTTPS 的
WebSocket Relay。在 Relay 候选准备完成后，WebSocket 最迟在前三种 carrier 合计
30 秒预算后开始建立，且该上界不随下发的 Relay 地址数量增长。

10 秒通常足以让可达路径完成 TURN challenge 和认证分配，同时把四种 carrier 的完整
回退限制在固定范围。极慢路径可能在操作系统最终能够连接前被放弃；运营者应提供可达的
WebSocket Relay，并让控制器下发的 Relay 列表保持有序且精简。
