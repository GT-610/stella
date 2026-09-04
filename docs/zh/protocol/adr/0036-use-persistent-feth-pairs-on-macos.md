# ADR 0036：在 macOS 上使用持久 feth pair 提供二层接入

- 状态：已接受
- 日期：2026-09-04

## 背景

Stella 必须处理完整以太网帧。macOS 的 `utun` 只提供三层接口，无法承载 ARP、以太网
广播或任意非 IP 帧。内核扩展会引入 Apple 已弃用接口的安装与签名要求；DriverKit 系统
扩展或特权 helper 则会显著扩大首个 macOS 版本的部署和安全边界。

macOS 内置的 fake Ethernet（`feth`）接口可以像 Linux veth 一样成对连接。主机可把一端
当作普通以太网接口配置；另一端的收包需要 BPF，发包需要 AF_NDRV。仅使用 BPF 注入会受到
2,048 字节上限。这些接口层级很低，且部分行为没有正式文档。

`tun-rs` 2.8.8 已实现 feth、BPF、AF_NDRV、可中断同步 I/O 和持久设备复用。在 Stella 内
重复编写这些 unsafe ioctl 与 socket 代码只会复制现有上游实现，并不会改善协议边界。

## 决策

macOS 的 `stella-tap` 后端精确依赖发布版 `tun-rs` 2.8.8，关闭默认 feature，仅启用
`interruptible`。Stella 不复制、fork 或暴露上游 unsafe 实现。

每个 macOS TAP 必须显式配置两个不同的数值型 `feth<N>` 名称：

- `TapConfig::name` 是宿主可见接口，用户在这一端配置 IP 或运行 DHCP；
- `TapConfig::peer_name` 是由 BPF 与 AF_NDRV 绑定的报文 I/O 端。

物理接口和隐式名称分配会被拒绝。客户端在版本 1 配置中以 `tap_adapter`、`tap_peer`
保存两端，并在幂等 join 和冲突检查中比较完整 pair。

创建设备时选择 `Layer::L2`，启用复用与持久化，并使用 nonblocking、interruptible I/O。
读取保留 BPF 返回的一整个以太网帧；写入使用上游 AF_NDRV 路径，因此可发送超过 2,048
字节的帧。任何短写都视为错误。

打开 pair 时，网络策略请求的 MTU 会被已有的更低接口 MTU 限制。之后显式设置 MTU 会
同时更新 pair 两端；协议的完整帧上限仍独立执行。

协作的 Stella 进程会在 root 所有、权限为 `0700` 的 `/var/run/stella/` 中获取规范化 pair
锁；即使交换两个名称，锁键也相同。第二个实例会得到类型化占用错误，而不是重新配对活动
客户端已经持有的接口。

只有读写处于 pending 时，取消操作才触发上游 interrupt event。操作结束会清除 pending
状态并 reset event；空闲取消不会污染下一次操作，已经完成的帧在与取消同时发生时优先。

首个实现要求客户端以 root 运行，不安装 kext、DriverKit 扩展、launch daemon、特权
helper 或独立报文服务。`destroy` 和 `Drop` 停止 I/O、释放锁，并把宿主可见接口置 down，
但不删除 pair。下次启动会复用同名接口，因此宿主 IP 配置可在本次开机期间跨客户端重启
保留。测试或管理员工具只有在确认所有权后才可显式删除 pair。

## 影响

macOS 客户端无需增加 Stella 自有的 unsafe 网络代码，即可提供与 Windows 相同的完整帧
`TapDevice` 契约。ARP、广播、多播、非 IP 以太网以及 Stella 上限内的大帧都可使用 macOS
内置设施。

活动数据平面必须以 root 运行，正常退出后持久 feth 仍会显示。advisory lock 只能防止协作
进程冲突。管理员必须为每个 Stella 网络分配两个不同的 feth 名称，并且不能在 I/O peer
上配置宿主 IP。

Stella 依赖固定的 `tun-rs` 2.8.8 行为。未来升级上游版本时，必须重新执行真实 feth 生命周期、
取消、MTU、大帧、复用、锁和双节点二层验证。

本里程碑拒绝三层 `utun`、复制 unsafe ioctl、已弃用 kext，以及新的特权 helper 或 daemon。
若未来要把 root 权限收窄到独立组件，必须在新的 ADR 中设计安装、升级、IPC 和威胁模型。
