import assert from 'node:assert/strict';
import { existsSync, readFileSync, readdirSync, unlinkSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';

// Exercise publication through a real build, including routes, feeds and tags.
const created = [];
const marker = 'draft-publication-regression-fixture';
const build = () => {
  const result = spawnSync('npm', ['run', 'build'], {
    encoding: 'utf8', env: { ...process.env, ASTRO_TELEMETRY_DISABLED: '1' },
  });
  assert.equal(result.status, 0, result.stdout + result.stderr);
};
const outputFiles = function* (directory) {
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) yield* outputFiles(path);
    else if (/\.(html|xml)$/.test(path)) yield path;
  }
};

try {
  for (const collection of ['posts', 'labs']) {
    const path = `src/content/${collection}/${marker}.md`;
    writeFileSync(path, `---
title: ${marker}
description: ${marker}
summary: ${marker}
pubDate: 2026-01-01
draft: true
tags: [${marker}]
difficulty: Easy
techniques: [Enumeration]
---
${marker}
`, { flag: 'wx' });
    created.push(path);
  }
  build();
  for (const section of ['posts', 'labs', 'tags']) {
    assert(!existsSync(`dist/${section}/${marker}/index.html`), `Draft route exposed in ${section}`);
  }
  for (const path of outputFiles('dist')) {
    assert(!readFileSync(path, 'utf8').includes(marker), `Draft leaked into ${path}`);
  }
  for (const path of ['dist/posts/vulnzoo/index.html', 'dist/labs/editor/index.html']) {
    assert(existsSync(path), `Published route missing: ${path}`);
  }
  assert(readFileSync('dist/rss.xml', 'utf8').includes('/posts/vulnzoo/'), 'Published post missing from RSS');
  console.log('Draft publication checks passed: no routes, listings, tags, RSS or sitemap leaks.');
} finally {
  for (const path of created) unlinkSync(path);
  // Leave only the real content in the preview/deployment artifact.
  if (created.length) build();
}
