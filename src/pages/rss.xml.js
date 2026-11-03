import rss from '@astrojs/rss';
import { getCollection } from 'astro:content';

export async function GET(context) {
  const posts = (await getCollection('posts', ({ data }) => !data.draft)).sort((a, b) => b.data.pubDate.valueOf() - a.data.pubDate.valueOf());
  return rss({
    title: 'd4str3k — Security research and projects',
    description: 'Product security projects, vulnerability research and updates by d4str3k.',
    site: context.site,
    items: posts.map((post) => ({
      title: post.data.title,
      pubDate: post.data.pubDate,
      description: post.data.description,
      link: new URL(`posts/${post.id}/`, context.site).href,
    })),
    customData: `<language>en-us</language>`,
  });
}