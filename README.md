# d4str3k — Security portfolio

Personal portfolio, security projects, blog posts and Hack The Box write-ups, built with Astro and deployed to GitHub Pages.

## Development

Use Node.js 24 LTS (minimum supported version: 22.23.4) and npm.

```sh
npm ci
npm run dev
```

## Validation

```sh
npm run check
npm run build
npm run test:drafts
npm audit
```

`test:drafts` creates temporary draft entries, builds the site, checks that drafts are absent from pages, tags, feeds and sitemaps, then removes the fixtures and rebuilds the real site. Run it without another build or content-editing process in progress.

`npm run preview` serves the compiled site locally.

## Content

- Posts: `src/content/posts/*.md`
- Labs: `src/content/labs/*.md`
- Collection schemas: `src/content.config.ts`
- Shared navigation and metadata: `src/layouts/BaseLayout.astro`
- Project descriptions: `src/pages/projects.astro`

Posts use `title`, `description`, `pubDate`, optional `author`, `tags`, `image` and `draft`. For cover images, include `imageWidth` and `imageHeight` to reserve their display space. Assets referenced with a leading slash live in `public/`.

Labs additionally use `summary`, `difficulty` (Easy, Medium, Hard, Insane or Not rated), optional `difficultySource`, `techniques` and `lang` (en or es). Use level-two Markdown headings for the generated contents list. Screenshots should include descriptive alternative text, intrinsic width/height and lazy loading.

Setting `draft: true` excludes an entry from public routes and listings. Draft posts are also excluded from tags and RSS. The local font is loaded from `public/fonts/FiraCode-VF.woff2`.

## Deployment

The GitHub Actions workflow in `.github/workflows/deploy.yml` builds with Node.js 24 and deploys pushes to `main`. The site URL and trailing-slash convention are configured in `astro.config.mjs`. GitHub Pages must use GitHub Actions as its source.

## Credits

The design is based on [Hugo Terminal by panr](https://github.com/panr/hugo-theme-terminal), ported to Astro by [Dennis Klappe](https://github.com/dennisklappe/astro-theme-terminal). Original theme attribution is retained in the footer and MIT license.
