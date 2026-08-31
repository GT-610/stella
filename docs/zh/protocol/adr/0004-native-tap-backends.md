# ADR 0004：通过统一安全接口使用原生 TAP 后端

- 状态：已接受
- 日期：2026-08-29

## 背景

二层透明性需要完整以太网帧。Windows 使用 TAP-Windows 设备句柄和控制码，Linux 使用
`/dev/net/tun`，macOS 需要合适的二层后端策略。

## 决策

`stella-tap` 提供同步 `TapDevice` 契约，涵盖设备生命周期、帧读写、MAC 地址访问和 MTU
更新。平台模块由 `cfg` 选择。Windows 使用 `windows` crate 和 `DeviceIoControl`，不使用
`winapi`。Windows 后端优先实现和测试；未支持平台返回类型化错误，不会用三层接口静默
模拟二层。

## 后果

上层不依赖操作系统句柄，非安全 FFI 被限制在后端。同步契约易于测试，也可通过专用阻塞
任务与 Tokio 集成；平台安装和权限要求仍不可避免。
