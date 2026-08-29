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
            { text: 'Overview', link: '/protocol/spec/00-overview' }
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
            { text: '0006: Licensing', link: '/protocol/adr/0006-license-boundaries' }
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
            { text: 'Architecture', link: '/development/architecture' }
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
