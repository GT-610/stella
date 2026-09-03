# 参考实现架构

本页说明 Stella 参考实现的 crate 边界。互操作性要求以
[协议规范](/protocol/spec/00-overview)为准。

## 依赖方向

`stella-client` 依赖 `stella-common`、`stella-proto`、`stella-tap`、
`stella-transport`、`stella-crypto` 和 `stella-control`。`stella-server`
依赖 `stella-common`、`stella-proto`、`stella-crypto` 和 `stella-control`。
低层 crate 不得依赖任一二进制 crate。

`stella-common` 保存不含线上布局的共享小型值类型；`stella-proto` 负责协议常量、
消息、验证和字节级编码；`stella-tap` 提供安全的 TAP 设备契约和平台实现，Windows 使用
原生 TAP-Windows，macOS 使用固定的 `tun-rs` 2.8.8 feth/BPF/AF_NDRV 实现并在外层执行
Stella 的边界、锁、取消与生命周期规则；
`stella-transport` 提供可替换的有界数据报抽象；`stella-crypto` 管理身份、会话密钥、
数据包保护、重放窗口和秘密清零；`stella-control` 负责控制通道的分帧、序列、关联和
TLS 导出器证明记录。

`stella-server` 管理控制器配置、持久授权状态、已认证控制会话、成员关系、对等快照和
管理 CLI。`stella-client` 管理配置和 CLI、控制器会话、虚拟交换状态、TAP 生命周期、
传输会话、转发、重连和有序关闭。控制器不得成为单播数据的必经中继。

## 运行时和测试边界

客户端在 TAP 与数据平面之间的两个方向都使用有界路径；同步 TAP 操作不在异步执行器
工作线程上运行。队列必须有明确容量和溢出策略，日志不得包含私钥、Bearer 凭据或原始
用户以太网负载。控制器将每个连接和消息视为不可信，只有身份、版本、大小和授权检查
通过后才接受它们。向节点分发的状态带有 epoch 和有界租约，过期控制器数据最终失效。

测试分为值类型、状态机和解析器的单元测试，协议往返和畸形输入的属性测试，TAP 的
平台测试，回环传输上的控制器与客户端集成测试，以及在 Windows 真实 TAP 或 macOS
真实 feth pair 上验证 ARP、广播、多播、LAN discovery 和双向 IP 流量的端到端测试。
