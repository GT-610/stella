# ADR 0012：按稳定身份打开预安装的 TAP-Windows 适配器

- 状态：已接受
- 日期：2026-08-30

## 决策

`stella-tap` 打开已经安装的 TAP-Windows Adapter V9。驱动安装、适配器创建、移除、重命名、
启用/禁用、持久 MAC 更改和驱动重启由安装程序或管理员负责。适配器通过 IP Helper API
枚举，显式选择器可匹配连接友好名称或规范接口 GUID；未指定选择器时，必须恰好存在一个
候选项。实现打开 `\\.\Global\{interface-guid}.tap` 后还会验证驱动版本、MAC 和 MTU。

## 后果

客户端不会静默选择错误的 VPN 或网络适配器。TAP 的待处理 I/O 可由 `CancelIoEx` 取消，
关闭时会断开介质并释放句柄。
