import { defineConfig } from 'vitepress'

export default defineConfig({
  title: 'Stella',
  description: 'Open Layer-2 virtual LAN protocol and reference implementation',
  cleanUrls: true,
  lastUpdated: true,
  locales: {
    root: {
      label: 'English',
      lang: 'en'
    },
    zh: {
      label: '简体中文',
      lang: 'zh-CN',
      link: '/zh/',
      title: 'Stella',
      description: '开源的二层虚拟局域网协议与参考实现',
      themeConfig: {
        nav: [
          { text: '主页', link: '/zh/' },
          { text: '协议', link: '/zh/protocol/' },
          { text: '使用指南', link: '/zh/guide/' },
          { text: '命令行', link: '/zh/api/client-cli' },
          { text: '开发', link: '/zh/development/' }
        ],

        sidebar: {
          '/zh/protocol/': [
            {
              text: '协议',
              items: [
                { text: '协议概览', link: '/zh/protocol/' },
                { text: '概述', link: '/zh/protocol/spec/00-overview' },
                { text: '线上格式', link: '/zh/protocol/spec/01-wire-format' },
                { text: '控制平面', link: '/zh/protocol/spec/02-control-plane' },
                { text: '身份', link: '/zh/protocol/spec/03-identity' },
                { text: '网络模型', link: '/zh/protocol/spec/04-network-model' },
                { text: '发现', link: '/zh/protocol/spec/05-discovery' },
                { text: '广播', link: '/zh/protocol/spec/06-broadcast' },
                { text: '传输', link: '/zh/protocol/spec/07-transport' },
                { text: '安全', link: '/zh/protocol/spec/08-security' },
                { text: '版本控制', link: '/zh/protocol/spec/09-versioning' },
                { text: '勘误', link: '/zh/protocol/spec/10-errata' },
                { text: '自动连接', link: '/zh/protocol/spec/11-connectivity' },
                { text: 'Relay', link: '/zh/protocol/spec/12-relay' }
              ]
            },
            {
              text: '架构决策记录',
              collapsed: true,
              items: [
                { text: 'ADR 索引', link: '/zh/protocol/adr/' },
                { text: '0001：Rust', link: '/zh/protocol/adr/0001-use-rust' },
                { text: '0002：控制器', link: '/zh/protocol/adr/0002-centralized-controller' },
                { text: '0003：传输', link: '/zh/protocol/adr/0003-pluggable-data-transport' },
                { text: '0004：TAP 后端', link: '/zh/protocol/adr/0004-native-tap-backends' },
                { text: '0005：工作区', link: '/zh/protocol/adr/0005-cargo-workspace' },
                { text: '0006：许可证', link: '/zh/protocol/adr/0006-license-boundaries' },
                { text: '0007：控制 TLS', link: '/zh/protocol/adr/0007-control-plane-over-tls' },
                { text: '0008：线上编码', link: '/zh/protocol/adr/0008-explicit-wire-encoding' },
                { text: '0009：密码学', link: '/zh/protocol/adr/0009-cryptographic-suite' },
                { text: '0010：泛洪', link: '/zh/protocol/adr/0010-head-end-flooding' },
                { text: '0011：配置', link: '/zh/protocol/adr/0011-toml-configuration' },
                { text: '0012：TAP-Windows', link: '/zh/protocol/adr/0012-preinstalled-tap-windows-adapters' },
                { text: '0013：控制通道', link: '/zh/protocol/adr/0013-shared-control-channel-crate' },
                { text: '0014：控制器状态', link: '/zh/protocol/adr/0014-redb-controller-state' },
                { text: '0015：身份文件', link: '/zh/protocol/adr/0015-protect-controller-identity-files' },
                { text: '0016：TLS 初始化', link: '/zh/protocol/adr/0016-initialize-controller-tls-identity' },
                { text: '0017：对等租约', link: '/zh/protocol/adr/0017-persist-peer-leases-with-endpoints' },
                { text: '0018：控制器运行时', link: '/zh/protocol/adr/0018-bound-controller-runtime' },
                { text: '0019：会话认证', link: '/zh/protocol/adr/0019-authenticate-control-sessions-before-authority-use' },
                { text: '0020：活动请求', link: '/zh/protocol/adr/0020-serve-authenticated-control-requests-from-atomic-views' },
                { text: '0021：授权刷新', link: '/zh/protocol/adr/0021-refresh-membership-grants-on-monotonic-deadlines' },
                { text: '0022：客户端状态', link: '/zh/protocol/adr/0022-rebuild-client-state-from-controller' },
                { text: '0023：客户端数据运行时', link: '/zh/protocol/adr/0023-bound-windows-client-data-runtime' },
                { text: '0024：ICE 自动连接', link: '/zh/protocol/adr/0024-use-ice-for-connectivity' },
                { text: '0025：Relay 兜底', link: '/zh/protocol/adr/0025-maintain-warm-relay-fallback' },
                { text: '0026：已验证路径', link: '/zh/protocol/adr/0026-bind-sessions-to-validated-paths' },
                { text: '0027：连接状态分发', link: '/zh/protocol/adr/0027-separate-connectivity-from-membership-records' },
                { text: '0029：HTTP 代理隧道', link: '/zh/protocol/adr/0029-tunnel-websocket-through-http-proxy' },
                { text: '0030：代理控制引导', link: '/zh/protocol/adr/0030-bootstrap-control-through-http-proxy' },
                { text: '0031：Relay 建立期限', link: '/zh/protocol/adr/0031-bound-relay-carrier-establishment' },
                { text: '0032：Relay DNS 期限', link: '/zh/protocol/adr/0032-bound-relay-dns-preparation' },
                { text: '0033：Relay 刷新', link: '/zh/protocol/adr/0033-preserve-relay-carrier-on-refresh' },
                { text: '0034：Relay 热恢复', link: '/zh/protocol/adr/0034-recover-relay-without-restarting-direct-sessions' },
                { text: '0035：控制重连保活', link: '/zh/protocol/adr/0035-preserve-forwarding-during-controller-reconnect' },
                { text: '0036：macOS feth', link: '/zh/protocol/adr/0036-use-persistent-feth-pairs-on-macos' }
              ]
            }
          ],
          '/zh/guide/': [
            {
              text: '使用指南',
              items: [
                { text: '项目状态', link: '/zh/guide/' },
                { text: 'Windows 开发环境', link: '/zh/guide/windows-development' },
                { text: 'macOS 开发环境', link: '/zh/guide/macos-development' },
                { text: '部署 Windows 控制器', link: '/zh/guide/server-deployment' }
              ]
            }
          ],
          '/zh/api/': [
            {
              text: '命令行参考',
              items: [
                { text: '客户端', link: '/zh/api/client-cli' },
                { text: '服务器管理', link: '/zh/api/server-cli' }
              ]
            }
          ],
          '/zh/development/': [
            {
              text: '开发',
              items: [
                { text: '概览', link: '/zh/development/' },
                { text: '参考实现架构', link: '/zh/development/architecture' },
                { text: '协议编解码器', link: '/zh/development/protocol-codec' },
                { text: '密码学实现', link: '/zh/development/cryptography' },
                { text: '数据报传输', link: '/zh/development/transport' },
                { text: 'Windows TAP', link: '/zh/development/tap-windows' },
                { text: 'macOS feth TAP', link: '/zh/development/tap-macos' },
                { text: '控制通道', link: '/zh/development/control-channel' },
                { text: '控制器', link: '/zh/development/controller' },
                { text: '客户端控制平面', link: '/zh/development/client-control' },
                { text: '客户端数据平面', link: '/zh/development/client-data-plane' }
              ]
            }
          ]
        },

        footer: {
          message: '协议规范采用 CC BY-SA 4.0 许可。',
          copyright: '参考实现采用 GPL-3.0-only 许可。'
        }
      }
    }
  },
  themeConfig: {
    nav: [
      { text: 'Home', link: '/' },
      { text: 'Protocol', link: '/protocol/' },
      { text: 'Guide', link: '/guide/' },
      { text: 'Development', link: '/development/' }
    ],

    sidebar: {
      '/protocol/': [
        {
          text: 'Protocol specification',
          items: [
            { text: 'About the specification', link: '/protocol/' },
            { text: 'Overview', link: '/protocol/spec/00-overview' },
            { text: 'Wire format', link: '/protocol/spec/01-wire-format' },
            { text: 'Control plane', link: '/protocol/spec/02-control-plane' },
            { text: 'Identity', link: '/protocol/spec/03-identity' },
            { text: 'Network model', link: '/protocol/spec/04-network-model' },
            { text: 'Discovery', link: '/protocol/spec/05-discovery' },
            { text: 'Broadcast', link: '/protocol/spec/06-broadcast' },
            { text: 'Transport', link: '/protocol/spec/07-transport' },
            { text: 'Security', link: '/protocol/spec/08-security' },
            { text: 'Versioning', link: '/protocol/spec/09-versioning' },
            { text: 'Errata', link: '/protocol/spec/10-errata' },
            { text: 'Automatic connectivity', link: '/protocol/spec/11-connectivity' },
            { text: 'Relay', link: '/protocol/spec/12-relay' }
          ]
        },
        {
          text: 'Architecture decisions',
          collapsed: true,
          items: [
            { text: 'ADR index', link: '/protocol/adr/' },
            { text: '0001: Rust', link: '/protocol/adr/0001-use-rust' },
            { text: '0002: Controller', link: '/protocol/adr/0002-centralized-controller' },
            { text: '0003: Transport', link: '/protocol/adr/0003-pluggable-data-transport' },
            { text: '0004: TAP backends', link: '/protocol/adr/0004-native-tap-backends' },
            { text: '0005: Workspace', link: '/protocol/adr/0005-cargo-workspace' },
            { text: '0006: Licensing', link: '/protocol/adr/0006-license-boundaries' },
            { text: '0007: Control TLS', link: '/protocol/adr/0007-control-plane-over-tls' },
            { text: '0008: Wire encoding', link: '/protocol/adr/0008-explicit-wire-encoding' },
            { text: '0009: Cryptography', link: '/protocol/adr/0009-cryptographic-suite' },
            { text: '0010: Flooding', link: '/protocol/adr/0010-head-end-flooding' },
            { text: '0011: Configuration', link: '/protocol/adr/0011-toml-configuration' },
            { text: '0012: TAP-Windows', link: '/protocol/adr/0012-preinstalled-tap-windows-adapters' },
            { text: '0013: Control channel', link: '/protocol/adr/0013-shared-control-channel-crate' },
            { text: '0014: Controller state', link: '/protocol/adr/0014-redb-controller-state' },
            { text: '0015: Identity files', link: '/protocol/adr/0015-protect-controller-identity-files' },
            { text: '0016: TLS initialization', link: '/protocol/adr/0016-initialize-controller-tls-identity' },
            { text: '0017: Peer leases', link: '/protocol/adr/0017-persist-peer-leases-with-endpoints' },
            { text: '0018: Controller runtime', link: '/protocol/adr/0018-bound-controller-runtime' },
            { text: '0019: Session authentication', link: '/protocol/adr/0019-authenticate-control-sessions-before-authority-use' },
            { text: '0020: Active requests', link: '/protocol/adr/0020-serve-authenticated-control-requests-from-atomic-views' },
            { text: '0021: Grant refresh', link: '/protocol/adr/0021-refresh-membership-grants-on-monotonic-deadlines' },
            { text: '0022: Client state', link: '/protocol/adr/0022-rebuild-client-state-from-controller' },
            { text: '0023: Client data runtime', link: '/protocol/adr/0023-bound-windows-client-data-runtime' },
            { text: '0024: ICE connectivity', link: '/protocol/adr/0024-use-ice-for-connectivity' },
            { text: '0025: Relay fallback', link: '/protocol/adr/0025-maintain-warm-relay-fallback' },
            { text: '0026: Validated paths', link: '/protocol/adr/0026-bind-sessions-to-validated-paths' },
            { text: '0027: Connectivity state', link: '/protocol/adr/0027-separate-connectivity-from-membership-records' },
            { text: '0028: Authority migration', link: '/protocol/adr/0028-migrate-connectivity-authority-state' },
            { text: '0029: HTTP proxy tunnel', link: '/protocol/adr/0029-tunnel-websocket-through-http-proxy' },
            { text: '0030: Proxy control bootstrap', link: '/protocol/adr/0030-bootstrap-control-through-http-proxy' },
            { text: '0031: Relay establishment bounds', link: '/protocol/adr/0031-bound-relay-carrier-establishment' },
            { text: '0032: Relay DNS bounds', link: '/protocol/adr/0032-bound-relay-dns-preparation' },
            { text: '0033: Preserve relay carrier', link: '/protocol/adr/0033-preserve-relay-carrier-on-refresh' },
            { text: '0034: Hot relay recovery', link: '/protocol/adr/0034-recover-relay-without-restarting-direct-sessions' },
            { text: '0035: Preserve reconnect forwarding', link: '/protocol/adr/0035-preserve-forwarding-during-controller-reconnect' },
            { text: '0036: macOS feth pairs', link: '/protocol/adr/0036-use-persistent-feth-pairs-on-macos' }
          ]
        }
      ],
      '/guide/': [
        {
          text: 'User guide',
          items: [
            { text: 'Project status', link: '/guide/' },
            { text: 'Windows development setup', link: '/guide/windows-development' },
            { text: 'macOS development setup', link: '/guide/macos-development' },
            { text: 'Deploy a Windows controller', link: '/guide/server-deployment' }
          ]
        }
      ],
      '/development/': [
        {
          text: 'Development',
          items: [
            { text: 'Overview', link: '/development/' },
            { text: 'Architecture', link: '/development/architecture' },
            { text: 'Protocol codec', link: '/development/protocol-codec' },
            { text: 'Cryptography', link: '/development/cryptography' },
            { text: 'Transport', link: '/development/transport' },
            { text: 'Windows TAP', link: '/development/tap-windows' },
            { text: 'macOS feth TAP', link: '/development/tap-macos' },
            { text: 'Control channel', link: '/development/control-channel' },
            { text: 'Controller', link: '/development/controller' },
            { text: 'Client control plane', link: '/development/client-control' },
            { text: 'Client data plane', link: '/development/client-data-plane' }
          ]
        }
      ],
      '/api/': [
        {
          text: 'Command-line reference',
          items: [
            { text: 'Client', link: '/api/client-cli' },
            { text: 'Server administration', link: '/api/server-cli' }
          ]
        }
      ]
    },

    socialLinks: [
      { icon: 'github', link: 'https://github.com/GT-610/stella' }
    ],

    search: { provider: 'local' },
    footer: {
      message: 'Protocol specification licensed under CC BY-SA 4.0.',
      copyright: 'Reference implementation licensed under GPL-3.0-only.'
    }
  }
})
