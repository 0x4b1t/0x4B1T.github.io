// @ts-check
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';

// https://astro.build/config
export default defineConfig({
	site: 'https://0x4b1t.github.io'
	integrations: [
		starlight({
			title: '0x4B1T',
			social: [{ icon: 'github', label: 'GitHub', href: 'https://github.com/kris3c' }],
			sidebar: [
				//{
				//	label: 'Guides',
				//	items: [
				//		// Each item here is one entry in the navigation menu.
				//		{ label: 'Example Guide', slug: 'guides/example' },
				//	],
				//},
				{
                                        label: 'Homepage',
                                        autogenerate: { directory: "homepage" }
                                },
				//{
				//	label: 'Reference',
				//	autogenerate: { directory: 'reference' },
				//},
				{
					label: 'Hackries',
					autogenerate: { directory: "hackries" }

				},
				{
                                        label: 'Articles',
                                        autogenerate: { directory: "articles" }

                                },
				{
                                        label: 'Writeups',
                                        autogenerate: { directory: "writeups" }

                                },
				 {
                                        label: 'Projects',
                                        autogenerate: { directory: "projects" }

                                },

				{
                                        label: 'About',
                                        autogenerate: { directory: "about" }

                                },

			],
		}),
	],
});
