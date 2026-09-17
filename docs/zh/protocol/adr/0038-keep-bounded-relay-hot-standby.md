# ADR 0038：保留有界 relay 热备用路径

- 状态：已接受
- 日期：2026-09-13
- 取代：ADR 0025 的单 allocation 部署基线

## 背景

单个温备 relay 免去启动时等待直连超时，但仍是单点。重启、carrier 失败或防火墙变化会撤销
唯一 relay 候选，relay-only peer 必须等待重建。可靠流发送还可能等待 I/O 和权限准备，
若数据循环直接等待，会阻塞无关的 UDP、TAP、控制和其他 relay 工作。

## 决策

参考客户端最多维持两个不同的温备路径，以精确的 `(relay-id, carrier)` 标识。
选择保留控制器优先级以及 UDP、TCP、TLS、Secure WebSocket 的回退顺序；
同一标识的重复数字地址不占第二个名额。

两个 allocation 作为严格排序的 relay 候选发布并同时接收流量。发送选择与 peer 端点的
relay 身份及 carrier 精确匹配的 allocation，仅在该 allocation 上准备权限。

失败只撤销受影响路径。直连和另一温备保留，后台使用有界 carrier 期限及 full-jitter
重连退避补充空位。连接 generation 轮换立即公布存活集合。

每个 allocation 有独立的有界客户端命令队列。数据运行时将完整数据报入队而不等待
socket 或 stream I/O；队列溢出丢弃新数据报。异步投递失败停止该 allocation 并进入正常恢复流程。

## 影响

一个 allocation 被替换时，relay-only 节点可继续使用已建立的另一 carrier 或服务。
慢速可靠流不会阻塞客户端事件循环中的直连或其他 allocation。
第二个 allocation 即使未被选中也消耗状态与保活带宽，部署须计入这一有界成本。
双路径提高可用性，但不提供基于延迟的地域选择；测量路径评分仍需单独决策。
