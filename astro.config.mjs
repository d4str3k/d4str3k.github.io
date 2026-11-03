// @ts-check
import { defineConfig } from 'astro/config';
import sitemap from '@astrojs/sitemap';

// https://astro.build/config
export default defineConfig({
  site: 'https://d4str3k.github.io',
  trailingSlash: 'always',
  compressHTML: true,
  base: '/',
  integrations: [sitemap({ filter: (page) => !page.endsWith('/404/') })],
  markdown: {
    shikiConfig: {
      theme: 'css-variables',
      langs: [],
      wrap: true,
    },
  },
});
