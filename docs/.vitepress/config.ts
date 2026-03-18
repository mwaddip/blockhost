import { defineConfig } from 'vitepress';

export default defineConfig({
  title: 'BlockHost',
  description: 'Autonomous VM hosting, driven by blockchain.',
  srcExclude: ['plans/**'],
  head: [
    ['link', { rel: 'preconnect', href: 'https://fonts.googleapis.com' }],
    ['link', { rel: 'preconnect', href: 'https://fonts.gstatic.com', crossorigin: '' }],
    ['link', { href: 'https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap', rel: 'stylesheet' }],
    ['meta', { property: 'og:type', content: 'website' }],
    ['meta', { property: 'og:title', content: 'BlockHost Documentation' }],
    ['meta', { property: 'og:description', content: 'Autonomous VM hosting, driven by blockchain.' }],
    ['meta', { property: 'og:image', content: 'https://docs.blockhost.io/logo.jpg' }],
    ['meta', { property: 'og:url', content: 'https://docs.blockhost.io' }],
    ['meta', { name: 'twitter:card', content: 'summary' }],
  ],
  themeConfig: {
    logo: '/logo.jpg',
    siteTitle: false,
    nav: [
      { text: 'Website', link: 'https://blockhost.io' },
      { text: 'Telegram', link: 'https://t.me/BlockHostOS' },
    ],
    sidebar: [
      {
        text: 'Getting Started',
        items: [
          { text: 'What is BlockHost?', link: '/getting-started/what-is-blockhost' },
          { text: 'Quick Start', link: '/getting-started/quick-start' },
          { text: 'Supported Chains', link: '/getting-started/supported-chains' },
        ],
      },
      {
        text: 'Operator Guide',
        items: [
          { text: 'Build Guide', link: '/operator/build-guide' },
          { text: 'Wizard Walkthrough', link: '/operator/wizard-walkthrough' },
          { text: 'Post-Install', link: '/operator/post-install' },
          { text: 'Plan Management', link: '/operator/plan-management' },
          { text: 'Troubleshooting', link: '/operator/troubleshooting' },
        ],
      },
      {
        text: 'Developer Guide',
        items: [
          { text: 'Architecture', link: '/developer/architecture' },
          { text: 'Building an Engine', link: '/developer/building-an-engine' },
          { text: 'Building a Provisioner', link: '/developer/building-a-provisioner' },
          { text: 'Interface Contracts', link: '/developer/interface-contracts' },
          { text: 'Page Templates', link: '/developer/page-templates' },
          { text: 'Contributing', link: '/developer/contributing' },
        ],
      },
      {
        text: 'User Guide',
        items: [
          { text: 'Purchasing a Subscription', link: '/user/purchasing' },
          { text: 'Accessing Your VM', link: '/user/accessing-your-vm' },
          { text: 'Your NFT Explained', link: '/user/nft-explained' },
          { text: 'FAQ', link: '/user/faq' },
        ],
      },
      {
        text: 'Security',
        items: [
          { text: 'Threat Model', link: '/security/threat-model' },
          { text: 'Privilege Separation', link: '/security/privilege-separation' },
          { text: 'Audit Status', link: '/security/audit-status' },
        ],
      },
    ],
    socialLinks: [
      { icon: 'github', link: 'https://github.com/mwaddip/blockhost' },
    ],
  },
});
