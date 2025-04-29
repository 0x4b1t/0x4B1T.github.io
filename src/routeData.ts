import { defineRouteMiddleware } from '@astrojs/starlight/route-data'

export const onRequest = defineRouteMiddleware((context) => {
  const id = context.locals.starlightRoute.id || 'index'
  const data = context.locals.starlightRoute.entry?.data

  const ogImagePath = data?.ogImage || '/og-images/default.png'

  const ogImageUrl = new URL(ogImagePath, context.site)

  console.log('[Middleware] OG image set:', ogImageUrl.href)

  context.locals.starlightRoute.head.push({
    tag: 'meta',
    attrs: { property: 'og:image', content: ogImageUrl.href },
  })

  context.locals.starlightRoute.head.push({
    tag: 'meta',
    attrs: { name: 'twitter:image', content: ogImageUrl.href },
  })
})
