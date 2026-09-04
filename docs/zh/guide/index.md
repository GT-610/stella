# 项目状态

Stella 仍处于标准化前的活跃开发阶段。在第一个可互操作草案宣布稳定前，
协议版本 0.1 和所有公开 API 都可能变更。

版本 0.1 的协议草案、核心编解码器、密码学、UDP 传输、自托管控制器，以及 Windows
和 macOS 原生客户端数据平面已经实现。Windows 使用预安装的 TAP-Windows；macOS 使用
Stella 自有后端，通过持久内置 feth pair、BPF 收包和 AF_NDRV 发包，并由本地特权 helper
隔离 root 权限。

Windows 参考路径已在一台装有两块真实 TAP 适配器的主机上完成端到端验证，覆盖 ARP、
双向 IPv4 单播、IPv4 广播和多播，以及局域网发现。macOS 已提供可编译的 root-only
生命周期测试和等价双节点场景，但尚未提交一次特权运行报告。Linux 仍是架构要求，但没有
参考 TAP 后端，因此其构建只运行控制平面。

`stella-server` 与已配置的 Windows 或 macOS 客户端可以组成实验性虚拟局域网。Windows
每个网络需要一个 TAP-Windows；macOS 每个网络需要一个未占用的持久 feth pair，以及
一个授权给客户端用户的 root TAP helper。控制器和至少一种已配置 Relay 承载必须可达。客户端会自动收集直连 UDP
候选，并依次回退到 TURN UDP、TCP、TLS 和 Secure WebSocket；只要 Relay 成功，就不要求
手工映射客户端端口。Stella 不分配 IP，也不提供 DHCP。请按平台开发与客户端 CLI 指南
配置，且不要将此里程碑视为生产网络发布。
