# 开发

Stella 按“规范优先”方式开发。协议或公开 API 的变更只有在规范文本、架构决策、实现
和测试一致时才算完成。

## 仓库区域

- `protocol/spec/` 是规范协议源文件；
- `protocol/adr/` 记录长期有效的决策和权衡；
- `crates/` 包含 Rust 工作区；
- `docs/` 包含渲染后的指南和同步的协议阅读副本；
- `tests/` 随实现加入集成和端到端场景。

构建会在 VitePress 前运行 `docs:sync`，确保 `docs/protocol/` 下的生成文件与规范源
一致。不要直接修改这些生成文件。

[参考实现架构](./architecture.md)说明 crate 与运行时边界；[协议编解码器](./protocol-codec.md)
说明线上字节的解析与编码；[密码学实现](./cryptography.md)说明秘密所有权、密钥派生、
数据包保护与重放处理。
[数据报传输](./transport.md)说明可对象化传输契约、UDP 套接字、取消与截断防护。
[Windows TAP](./tap-windows.md)说明适配器选择、完整帧 I/O、MTU 与取消。
[macOS feth TAP](./tap-macos.md)说明 visible/peer 分工、BPF 收包、AF_NDRV 发包、持久
复用、独占锁和 root-only 验证。
[控制通道](./control-channel.md)说明异步分帧 I/O、消息所有权、序列、关联与导出器绑定
证明输入。
[控制器](./controller.md)说明 TLS 服务边界、事务性授权状态、管理命令和会话行为。
[客户端控制平面](./client-control.md)说明持久信任、认证、原子对等状态、心跳、
重连与失败关闭转发；[客户端数据平面](./client-data-plane.md)说明 TAP 工作线程
所有权、已认证对等路由、保活、端点固定和重新生成密钥。
