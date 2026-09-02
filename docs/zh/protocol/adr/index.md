# 架构决策记录

ADR 记录约束 Stella 协议或其参考实现的决策。已接受的记录除拼写或链接
修正外不可变更；决策发生变化时，必须由新的 ADR 取代旧记录。

本目录使用的状态为 `Proposed`、`Accepted`、`Superseded` 和 `Rejected`。

## 索引

- [0001：使用 Rust](./0001-use-rust.md)
- [0002：使用集中式自托管控制器](./0002-centralized-controller.md)
- [0003：使数据传输可插拔](./0003-pluggable-data-transport.md)
- [0004：通过统一安全接口使用原生 TAP 后端](./0004-native-tap-backends.md)
- [0005：将实现组织为 Cargo 工作区](./0005-cargo-workspace.md)
- [0006：分离实现与规范许可证](./0006-license-boundaries.md)
- [0007：通过 TLS 1.3 和 TCP 运行控制平面](./0007-control-plane-over-tls.md)
- [0008：使用显式且经过检查的线上编码](./0008-explicit-wire-encoding.md)
- [0009：使用 Stella 0.1 密码学套件](./0009-cryptographic-suite.md)
- [0010：对泛洪流量使用有界头端复制](./0010-head-end-flooding.md)
- [0011：使用 TOML 进行本地配置](./0011-toml-configuration.md)
- [0012：按稳定身份打开预安装的 TAP-Windows 适配器](./0012-preinstalled-tap-windows-adapters.md)
- [0013：在专用 crate 中共享控制通道机制](./0013-shared-control-channel-crate.md)
- [0014：在 redb 中存储控制器授权状态](./0014-redb-controller-state.md)
- [0015：使用原生 ACL 保护控制器身份文件](./0015-protect-controller-identity-files.md)
- [0016：显式初始化控制器 TLS 身份](./0016-initialize-controller-tls-identity.md)
- [0017：持久化带端点集合的对等租约](./0017-persist-peer-leases-with-endpoints.md)
- [0018：限制控制器运行时接纳与关闭](./0018-bound-controller-runtime.md)
- [0019：在使用授权状态前认证控制会话](./0019-authenticate-control-sessions-before-authority-use.md)
- [0020：从原子视图提供已认证控制请求](./0020-serve-authenticated-control-requests-from-atomic-views.md)
- [0021：按单调期限刷新成员授权](./0021-refresh-membership-grants-on-monotonic-deadlines.md)
- [0022：从控制器重建客户端转发状态](./0022-rebuild-client-state-from-controller.md)
- [0023：限制 Windows 客户端数据运行时](./0023-bound-windows-client-data-runtime.md)
- [0024：使用 ICE 和 STUN 建立自动对等连接](./0024-use-ice-for-connectivity.md)
- [0025：维持待命 Relay 兜底路径](./0025-maintain-warm-relay-fallback.md)
- [0026：将对等会话绑定到已验证路径](./0026-bind-sessions-to-validated-paths.md)
- [0027：将连接状态与成员记录分开分发](./0027-separate-connectivity-from-membership-records.md)
- [0029：通过显式 HTTP 代理建立 Secure WebSocket 隧道](./0029-tunnel-websocket-through-http-proxy.md)
- [0030：通过本地 HTTP 代理引导控制器 TLS](./0030-bootstrap-control-through-http-proxy.md)
- [0031：限制 Relay carrier 建立时间](./0031-bound-relay-carrier-establishment.md)
- [0032：限制 Relay DNS 准备时间](./0032-bound-relay-dns-preparation.md)
- [0033：刷新时保留可达的 Relay carrier](./0033-preserve-relay-carrier-on-refresh.md)
- [0034：恢复 Relay 时不重启直连会话](./0034-recover-relay-without-restarting-direct-sessions.md)
- [0035：控制器重连期间保留有效转发](./0035-preserve-forwarding-during-controller-reconnect.md)
