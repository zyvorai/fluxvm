import {themes as prismThemes} from 'prism-react-renderer';
import type {Config} from '@docusaurus/types';
import type * as Preset from '@docusaurus/preset-classic';

// This runs in Node.js - Don't use client-side code here (browser APIs, JSX...)

const config: Config = {
  title: 'FluxVM',
  tagline: 'Disposable Compute Engine — secure, isolated, short-lived VMs via Firecracker, Cloud Hypervisor, QEMU/KVM, and the FluxVM hypervisor.',
  favicon: 'img/favicon.svg',

  future: {
    v4: true, // Improve compatibility with the upcoming Docusaurus v4
  },

  url: 'https://zyvorai.github.io',
  baseUrl: '/fluxvm/',

  organizationName: 'zyvorai',
  projectName: 'fluxvm',

  onBrokenLinks: 'warn',

  markdown: {
    // The existing docs/ corpus was written as plain Markdown for GitHub
    // rendering, not MDX — force CommonMark parsing so raw `<`/`!`/`{`
    // characters in prose don't get misread as JSX.
    format: 'md',
    hooks: {
      onBrokenMarkdownLinks: 'warn',
    },
  },

  i18n: {
    defaultLocale: 'en',
    locales: ['en'],
  },

  presets: [
    [
      'classic',
      {
        docs: {
          // Serve the repo's existing docs/ tree directly rather than
          // hand-curating a separate copy — see website/README.md.
          path: '../docs',
          routeBasePath: 'docs',
          sidebarPath: './sidebars.ts',
          editUrl: 'https://github.com/zyvorai/fluxvm/tree/main/docs/',
        },
        blog: false,
        theme: {
          customCss: './src/css/custom.css',
        },
      } satisfies Preset.Options,
    ],
  ],

  themeConfig: {
    colorMode: {
      respectPrefersColorScheme: true,
    },
    navbar: {
      title: 'FluxVM',
      logo: {
        alt: 'FluxVM',
        src: 'img/favicon.svg',
      },
      hideOnScroll: false,
      items: [
        {
          type: 'docSidebar',
          sidebarId: 'docsSidebar',
          position: 'right',
          label: 'Docs',
        },
        {
          href: 'https://github.com/zyvorai/fluxvm',
          label: 'GitHub',
          position: 'right',
        },
      ],
    },
    footer: {
      style: 'dark',
      links: [
        {
          title: 'Docs',
          items: [
            {label: 'Quick start', href: 'https://github.com/zyvorai/fluxvm#quick-start'},
            {label: 'Use cases', to: '/docs/use-cases'},
            {label: 'Product overview', to: '/docs/PRODUCT_OVERVIEW'},
            {label: 'Positioning', to: '/docs/POSITIONING'},
          ],
        },
        {
          title: 'Project',
          items: [
            {label: 'GitHub', href: 'https://github.com/zyvorai/fluxvm'},
            {
              label: 'Changelog',
              href: 'https://github.com/zyvorai/fluxvm/blob/main/CHANGELOG.md',
            },
            {
              label: 'License (Apache-2.0)',
              href: 'https://github.com/zyvorai/fluxvm/blob/main/LICENSE',
            },
          ],
        },
        {
          title: 'Zyvor Enterprise',
          items: [
            {label: 'zyvor.dev', href: 'https://zyvor.dev'},
            {label: 'sales@zyvor.dev', href: 'mailto:sales@zyvor.dev'},
          ],
        },
      ],
      copyright: `Copyright © ${new Date().getFullYear()} Zyvor AI Labs. FluxVM is Apache-2.0 licensed.`,
    },
    prism: {
      theme: prismThemes.github,
      darkTheme: prismThemes.dracula,
    },
  } satisfies Preset.ThemeConfig,
};

export default config;
