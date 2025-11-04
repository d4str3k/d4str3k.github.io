import { defineCollection, z } from 'astro:content';

const labs = defineCollection({
  schema: z.object({
    title: z.string(),
    summary: z.string().optional(),
    pubDate: z.date(),
    draft: z.boolean().optional(),
  }),
});

export const collections = {
  labs,
};