# macOS feth TAP 实现

`stella-tap` 把一个持久 macOS feth pair 暴露为 Stella 其余部分使用的同步、完整以太网帧
契约。后端直接使用发布版 `tun-rs` 2.8.8，不复制其 unsafe BPF、AF_NDRV 和 ioctl 代码。

## 接口分工

| Stella 字段 | 示例 | 作用 |
| --- | --- | --- |
| `TapConfig::name` / `tap_adapter` | `feth100` | 宿主可见端，用于 IP、DHCP 和抓包 |
| `TapConfig::peer_name` / `tap_peer` | `feth101` | Stella 专用 I/O 端；BPF 收包，AF_NDRV 发包 |

macOS 上两项都必填，必须不同，并严格使用数值型 `feth<N>`。`en0` 等物理接口会被拒绝。
ICE 主机候选枚举会排除 pair 两端，避免把虚拟接口误当作 underlay 路径。

## 创建与所有权

后端先在 `/var/run/stella/` 获取独占 advisory lock。该目录必须由 root 所有，且组和其他
用户不可访问。锁文件按排序后的 pair 命名，因此 `feth100/feth101` 与
`feth101/feth100` 会发生冲突。

随后通过 `tun-rs::DeviceBuilder` 选择 `Layer::L2`，设置显式 visible/peer 名称、
`reuse_dev(true)` 和 `persist(true)`。I/O 为 nonblocking，并使用可中断同步 API。首个
版本要求持有设备的客户端进程以 root 运行；Stella 不引入 helper、daemon、kext 或
DriverKit 组件。

`destroy` 和 `Drop` 会把宿主可见接口置 down、关闭报文 I/O 并释放锁，但刻意保留 pair。
下次客户端启动会重新配对并复用同名接口，因此宿主 IP 配置可在本次开机期间保留。管理员
只有在停止所有 owner 并确认准确名称后才应删除 pair。

## 帧 I/O 与取消

上游 macOS 二层实现使用 BPF 从 peer 接收完整帧，使用 AF_NDRV 向宿主可见端注入帧。
AF_NDRV 是必须的，因为 BPF 注入不能承载超过 2,048 字节的帧。Stella 在 I/O 前仍会验证
14 到 9,216 字节的完整帧范围，并拒绝短写。

互斥状态记录当前是否有 pending 操作以及是否已取消。空闲取消直接成功且不触发 event；
pending 取消会触发 event；操作完成会清除状态并 reset。完成与取消竞争时保留已经成功的
帧。取消 handle 为弱引用，设备关闭后仍是幂等 no-op。

## MTU

打开时读取已有 feth MTU，并应用该值与签名网络策略上限中的较小值，不会为了达到策略
上限而抬高宿主原有设置。`set_mtu` 会验证完整帧关系，并通过 `tun-rs` 同时更新 pair 两端。

应用程序只应在宿主可见端配置 IP；peer 仅用于报文 I/O 架构。

## 验证

无 root 单元测试覆盖 feth 名称、帧与 MTU 边界、空闲和 pending 取消、重复取消、event
reset、完成竞争及脱敏诊断。被忽略的 root-only 测试会创建隔离 pair，检查 MAC 和双端
MTU，抓取一个 4,096 字节 AF_NDRV 帧，取消 pending read，读取宿主产生的 ARP 帧，验证
锁冲突，并确认 down 但持久的同名复用。

```sh
cargo test -p stella-tap
cargo test -p stella-tap --test macos_tap --no-run
sudo "$(find target/debug/deps -type f -name 'macos_tap-*' -perm -111 -print -quit)" \
  --ignored --nocapture
```

完整双客户端场景见
[`tests/two-node-lan/README.md`](https://github.com/GT-610/stella/blob/main/tests/two-node-lan/README.md)，
它复用 Scapy verifier 验证 ARP、双向 IPv4、广播、多播、LAN discovery、关闭后持久化和
同名 pair 重启。
