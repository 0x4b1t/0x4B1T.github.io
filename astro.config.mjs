// @ts-check
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';

const GA_ID = 'G-V06K96LQTK';

// https://astro.build/config
export default defineConfig({
	site: 'https://0x4b1t.github.io',
	integrations: [
		starlight({
			title: '0x4B1T',
			favicon: 'faviicon.svg',
			logo: {src:'./public/logo.png'},
			social: [ {
      icon: 'heart', // You can use an appropriate icon for Buy Me a Coffee, e.g., 'coffee'
      label: 'Buy Me a Coffee',
      href: 'https://www.buymeacoffee.com/kris3c',
    },{ icon: 'github', label: 'GitHub', href: 'https://github.com/0x4b1t' }],
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

                                }
				

			],
			head: [
				{
					tag: 'script',
					attrs: {
						async: true,
						src: `https://www.googletagmanager.com/gtag/js?id=${GA_ID}`,
					},
				},
				{
					tag: 'script',
					Content: `
					  window.dataLayer = window.dataLayer || [];
					  function gtag(){dataLayer.push(arguments);}
					  gtag('js', new Date());
					  gtag('config', '${GA_ID}');
					`,
				},
			],
		}),
	],
});
