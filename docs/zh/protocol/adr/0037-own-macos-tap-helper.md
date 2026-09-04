# ADR 0037：在特权 helper 后维护自有 macOS TAP 后端

- 状态：已接受
- 日期：2026-09-04
- 取代：ADR 0036 中的 `tun-rs` 依赖与 root 客户端进程边界

## 背景

ADR 0036 为首个 macOS 二层里程碑选择了持久 feth pair 与发布版 `tun-rs` 后端。该原型
验证了 visible/peer 模型、BPF 收包、`AF_NDRV` 发包、取消和持久复用。进一步审查发现，
Stella 只使用该依赖很小的一部分，而它还维护与本项目无关的三层后端；准确的同步 feth
行为及其未解决问题也不受 Stella 控制。

让整个客户端以 root 运行，还会让控制器凭据、节点身份、传输 socket、Relay 状态和交换
逻辑获得本来只为 feth 设置与 raw packet descriptor 所需的权限。

本实现以 macOS SDK、公开 Darwin/XNU 行为和独立测试为依据。发布版 `tun-rs` 代码只作为
行为参考进行审阅，没有复制、vendor、fork 或链接。ZeroTier 的 MPL-2.0 `osdep` 材料只用于
理解独立 agent 的高层架构，没有复制或逐行翻译代码，也完全没有使用其 `nonfree` 目录。

## 决策

`stella-tap` 自己维护 macOS 后端。unsafe 代码集中在匹配 SDK 布局与系统调用的窄封装中。
实现将：

- 通过 Darwin 克隆 ioctl 创建显式数值型 feth；
- 使用绝对路径 `/sbin/ifconfig` 配对，不经过 shell，也不查找 `PATH`；
- 通过 nonblocking BPF 接收完整帧，严格解析内核 batch 中每个对齐记录，并在再次 poll 前
  耗尽用户态队列；
- 通过 nonblocking `AF_NDRV` 发送完整帧，包括超过 2,048 字节的帧；
- 使用 close-on-exec descriptor 和 nonblocking self-pipe 实现仅 pending 时生效的取消；
- 以回滚保护更新 pair MTU，并且只有全部设置完成后才记录持久 pair 所有权；
- 没有匹配的 root-owned Stella 所有权元数据时，拒绝接管已有接口。

普通 macOS `PlatformTapDevice` 是 proxy。前台 root `stella-tap-helper` 持有原生 TAP handle，
并在 `/var/run/stella-tap-helper.sock` 暴露带版本、长度前缀的 Unix socket 协议。启动时必须
显式指定获准 UID。socket 为 mode `0600` 且归该 UID 所有；helper 验证客户端 peer UID，
客户端则要求服务端 peer UID 为 root。

每个 helper 连接最多持有一个 feth pair。消息大小、诊断大小、每 session 命令队列和总
session 数量都有上限。独立取消消息可以中断 pending 设备 I/O。EOF 或协议错误会取消 I/O、
关闭原生设备、把 pair 置 down 并释放锁；pair 本身保留，以便本次开机期间复用。

helper 不接收控制器信任、注册或加入凭据、节点私钥、peer session key、UDP socket、Relay
allocation 或二层交换状态；这些仍位于无特权 `stella-client` 进程。

Windows 继续使用 Stella 现有的原生 TAP-Windows V9 后端。不引入 kext、DriverKit system
extension、`tun-rs` 依赖、fork 或 vendor 网络后端。

## 后果

Stella 需要维护更多 macOS 专用 unsafe 代码，并针对未来 SDK 与内核变化进行验证。相应地，
完整帧行为、取消规则、BPF 队列处理、所有权检查与错误模型都与 Stella 其余部分一起评审和
测试，而不是间接继承。

普通客户端不再需要 root。管理员仍需构建、安装并监督 root helper，并显式授权一个本地
UID。当前实现提供可运行的前台服务和安全 IPC 边界；把它打包为 launch daemon 属于独立的
部署任务。

真实 feth 生命周期和双节点测试仍需要 root，不能根据编译或无特权协议测试推断其结果。
