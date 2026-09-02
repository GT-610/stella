# 项目状态

Stella 仍处于标准化前的活跃开发阶段。在第一个可互操作草案宣布稳定前，
协议版本 0.1 和所有公开 API 都可能变更。

版本 0.1 的协议草案、核心编解码器、密码学、UDP 传输、TAP-Windows 访问、
自托管控制器控制平面与 Windows 客户端数据平面已经实现。Windows 参考路径已在一台
装有两块真实 TAP 适配器的 Windows 主机上完成端到端验证，覆盖 ARP、双向 IPv4
单播、IPv4 广播和多播，以及局域网发现。

Linux 和 macOS 仍是架构要求，但其设备后端不在第一个功能里程碑范围内。

`stella-server` 与已配置的 Windows 客户端可以组成实验性的虚拟局域网。每个客户端需要
已安装的 TAP-Windows 适配器，控制器和至少一种已配置 Relay 承载必须可达。客户端会自动
收集直连 UDP 候选，并依次回退到 TURN UDP、TCP、TLS 和 Secure WebSocket；只要 Relay
成功，就不要求用户为客户端手工映射端口。Stella 不分配 IP 地址，也不提供 DHCP。请按
Windows 部署和客户端 CLI 指南完成配置，且不要将此里程碑视为生产网络发布。
