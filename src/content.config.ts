import { defineCollection } from 'astro:content';
import { z } from 'astro/zod';
import { glob } from 'astro/loaders';

const posts = defineCollection({
  loader: glob({ pattern: '**/*.md', base: './src/content/posts' }),
  schema: z.object({
    title: z.string(),
    description: z.string().optional(),
    pubDate: z.coerce.date(),
    updatedDate: z.coerce.date().optional(),
    author: z.string().optional(),
    image: z.string().optional(),
    imageWidth: z.number().positive().optional(),
    imageHeight: z.number().positive().optional(),
    externalLink: z.string().optional(),
    tags: z.array(z.string()).default([]),
    draft: z.boolean().default(false),
  }),
});

const labs = defineCollection({
  loader: glob({ pattern: '**/*.md', base: './src/content/labs' }),
  schema: z.object({
    title: z.string(),
    summary: z.string().optional(),
    difficulty: z.enum(['Easy', 'Medium', 'Hard', 'Insane', 'Not rated']),
    difficultySource: z.url().optional(),
    techniques: z.array(z.string()).min(1),
    lang: z.enum(['en', 'es']).default('en'),
    pubDate: z.coerce.date(),
    author: z.string().optional(),
    image: z.string().optional(),
    imageWidth: z.number().positive().optional(),
    imageHeight: z.number().positive().optional(),
    externalLink: z.string().optional(),
    tags: z.array(z.string()).default([]),
    draft: z.boolean().default(false),
  }),
});

export const collections = { posts, labs };
