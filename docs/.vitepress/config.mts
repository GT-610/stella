import { defineConfig } from 'vitepress'

export default defineConfig({
  title: 'Stella',
  description: 'Open Layer-2 virtual LAN protocol and reference implementation',
  cleanUrls: true,
  lastUpdated: true,
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
            { text: 'Errata', link: '/protocol/spec/10-errata' }
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
            { text: '0011: Configuration', link: '/protocol/adr/0011-toml-configuration' }
          ]
        }
      ],
      '/guide/': [
        {
          text: 'User guide',
          items: [
            { text: 'Project status', link: '/guide/' },
            { text: 'Windows development setup', link: '/guide/windows-development' }
          ]
        }
      ],
      '/development/': [
        {
          text: 'Development',
          items: [
            { text: 'Overview', link: '/development/' },
            { text: 'Architecture', link: '/development/architecture' },
            { text: 'Protocol codec', link: '/development/protocol-codec' }
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
