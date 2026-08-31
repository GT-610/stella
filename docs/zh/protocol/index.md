# Stella 协议

本目录包含 Stella 协议规范的中文阅读版本。规范采用 CC BY-SA 4.0 许可，
实现可独立于 Rust 工作区使用该协议。

Stella 目前处于标准化前阶段。第一个可互操作草案标识为 `0.1`；在草案
宣布稳定前，预计仍会出现不兼容的线上变更。

## 目录结构

- `spec/` 包含规范性协议文本；
- `adr/` 记录架构决策及其理由。

## 规范索引

- `00-overview.md`：架构、术语、不变量和威胁模型；
- `01-wire-format.md`：数据平面头部、分片、保护和重放；
- `02-control-plane.md`：由 TLS 承载的消息和控制器状态机；
- `03-identity.md`：身份、注册、授权、epoch 和撤销；
- `04-network-model.md`：TAP、成员关系、隔离、交换和 MAC 状态；
- `05-discovery.md`：端点分发、选择、验证和存活性；
- `06-broadcast.md`：广播、多播、ARP 和未知单播复制；
- `07-transport.md`：数据报抽象、UDP、路径大小和背压；
- `08-security.md`：认证、对等握手、密钥和降级防护；
- `09-versioning.md`：协商、兼容性、注册表和升级；
- `10-errata.md`：已接受的更正和互操作性澄清。
