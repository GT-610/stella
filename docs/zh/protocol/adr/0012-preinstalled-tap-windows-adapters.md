# ADR 0012：从 Driver Store 配置每网络 TAP-Windows 适配器

- 状态：已接受
- 日期：2026-08-30
- 更新：2026-09-13

## 决策

已签名的 TAP-Windows Adapter V9 驱动包必须预先存在于 Windows Driver Store。Stella 不会
安装或移除驱动包，也不会持久修改 MAC、驱动 MTU 或重启微型端口。

`stella-tap` 管理 Stella root 设备的创建、命名、复用和删除。友好名称不存在时，它通过
SetupAPI 创建硬件 ID 为 `tap0901` 的网络设备，由 `DiInstallDevice` 选择已有签名驱动包，
等待 `NetCfgInstanceId`，然后设置连接名称。注册后的失败会清理半成品；删除后会等待接口
消失，除非 Windows 要求重启。

`stella-client` 将每个网络确定性映射为 `Stella <32位网络ID>`。`join` 在使用加入凭据前
确保设备存在；如果加入或配置持久化失败，会删除本次新建设备。`run` 在连接控制器前补建
丢失设备，普通关闭只设置 media-disconnected 并保留设备，`leave` 才删除。创建和删除需要
提升权限。

底层适配器仍通过 IP Helper API 枚举，选择器可匹配友好名称或规范接口 GUID；不存在的
GUID 不会被当作名称创建。实现打开 `\\.\Global\{interface-guid}.tap` 后还会验证驱动版本、
MAC 和 MTU。

## 后果

用户只需安装一次驱动包；加入多个网络会自动创建多个隔离的持久适配器，Windows CLI 不再
暴露适配器选择。离开网络只删除其确定性托管设备，失败的加入不会留下新建孤儿设备。
驱动 MTU 和持久 MAC 仍需外部管理员工具与微型端口重启。TAP 的待处理 I/O 可由
`CancelIoEx` 取消，关闭时会断开介质并释放句柄。
