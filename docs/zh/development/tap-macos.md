# macOS feth TAP 实现

`stella-tap` 把持久 macOS feth pair 暴露为与 Stella 其余部分一致的同步完整以太网帧契约。
实现由 Stella 自己维护：BPF 收包、`AF_NDRV` 发包；一个权限范围很窄的 root helper 通过
有界本地协议把该设备提供给普通用户客户端。

## 接口分工

| Stella 字段 | 示例 | 用途 |
| --- | --- | --- |
| `TapConfig::name` / `tap_adapter` | `feth100` | 宿主可见端，用于 IP、DHCP 和抓包 |
| `TapConfig::peer_name` / `tap_peer` | `feth101` | Stella 专用 I/O 端；BPF 收包，`AF_NDRV` 发包 |

macOS 上两项都必填，必须不同，并且严格符合数值型 `feth<N>`。`en0` 等物理接口会被拒绝。
ICE host candidate 枚举会排除两端，避免把虚拟 pair 误当 underlay 路径。

## 原生后端与所有权

root 后端先在 `/var/run/stella/` 获取规范化 pair 的独占锁；目录与锁文件都必须为 root
所有且仅 root 可访问。首次创建完整成功后，锁文件会记录 visible/peer 分工。复用必须匹配
该记录；Stella 不会重新配对无法证明由自身管理的已有 feth。

后端通过 Darwin 接口克隆 ioctl 创建缺失接口，再通过 feth driver-specific ioctl 查询和设置
peer 关系，并为每个新建的宿主可见接口分配随机的本地管理单播 MAC 地址，最后以
nonblocking、close-on-exec 打开报文 descriptor。已经正确配对时不会重复调用 `SET_PEER`；
两端均未配对时才建立关系，指向其他接口的冲突关系会被拒绝。准备过程记录本次创建的接口；
所有权记录提交前发生失败时，会恢复复用接口的状态，并且只销毁本次创建的部分。数字 feth
单元限制在内核支持的 `0..=9999` 范围内。

`destroy` 与 `Drop` 会关闭报文 I/O、把 pair 两端置 down 并释放锁，但不会删除接口。后续
helper session 可复用同名 pair，因此本次开机期间的宿主 IP 配置可以跨客户端重启保留。

## 帧 I/O 与取消

BPF 只用于接收。一次内核读取可能包含多个对齐记录，因此解析器在排入完整帧前会检查每个
header、捕获长度与原始长度、边界和对齐步长。再次 poll BPF 前必须先耗尽用户态帧队列；
截断记录会被拒绝。

发送始终走 `AF_NDRV`，包括超过 BPF 实际 2,048 字节注入上限的帧。短写会转为
`PartialFrameWrite`，诊断不包含帧内容。

nonblocking self-pipe 用于中断 `poll`。只有操作 pending 时才会触发；重复取消幂等；完成后
会排空 pipe，避免污染下一次操作。当报文 I/O 和取消同时 ready 时，先尝试报文 I/O，从而
保留已经完成的帧。

## 特权 helper

普通 macOS `PlatformTapDevice` 是 `MacosTapProxyDevice`。它连接
`/var/run/stella-tap-helper.sock`，并验证服务端 peer UID 为 root。前台
`stella-tap-helper` 必须以 root 运行且显式传入 `--allow-uid`；mode `0600` 的 socket 归该
用户所有，服务端还会独立验证每个客户端的 peer UID。

协议带版本和长度前缀，消息及诊断都有硬上限；每条连接只能打开一个 pair，设备命令队列
最多保留一个 pending 命令，服务最多接受 64 个 session。取消消息与 pending 请求独立传输。
客户端 EOF 会取消 I/O、把 pair 置 down、释放锁并关闭 session。helper 不接收节点私钥、
控制器凭据、Stella 会话密钥、UDP 数据报或 Relay 状态。

## MTU 行为

打开时读取 visible 端现有 MTU，并应用它与签名网络策略上限的较小值，不会为了达到策略
上限而抬高更低的宿主设置。显式 MTU 更新会修改 pair 两端；peer 更新失败时恢复 visible，
回滚再次失败则单独报告。

macOS 默认的 `net.link.fake.max_mtu` 可能低于 Stella 的协议上限。XNU 会在创建每个 feth 时
把该值复制为接口自身的上限，因此 root 后端会在创建 pair 任意一端之前，把这个运行时、
系统级上限提升到 `9202`。打开 pair 时还会核对每个接口的创建时上限；对以前按较低上限创建
的 feth 会返回明确错误。它不会降低已有值，也不会在退出时恢复旧值，因为那可能使其他进程
正在使用的 feth 接口失效。该设置不会跨系统重启持久化。

## 验证

无特权测试覆盖 feth 名称、ioctl 常量、严格 BPF batch、helper 消息边界与往返、peer 认证、
空闲与 pending 取消、断连清理、proxy 帧 I/O 和 MTU 请求。被忽略的 root-only 测试覆盖真实
feth 生命周期、MAC、两端 MTU、4,096 字节 `AF_NDRV` 发送、BPF 接收、锁、取消、持久化与
复用。

```sh
cargo test -p stella-tap
macos_tap_test=$(
  cargo test -p stella-tap --test macos_tap --no-run --message-format=json |
    python3 -c 'import json, sys
print(next(
    message["executable"]
    for message in map(json.loads, sys.stdin)
    if message.get("reason") == "compiler-artifact"
    and message.get("target", {}).get("name") == "macos_tap"
    and message.get("executable")
))'
)
sudo "$macos_tap_test" --ignored --nocapture
```

完整的 helper 双客户端场景见
[`tests/two-node-lan/README.md`](https://github.com/GT-610/stella/blob/main/tests/two-node-lan/README.md)。
