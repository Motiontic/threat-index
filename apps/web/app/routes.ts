import { index, type RouteConfig, route } from '@react-router/dev/routes';

export default [
  index('routes/home.tsx'),
  route('search', 'routes/search.tsx'),
  route('e/:id', 'routes/entry.tsx'),
  route('index/:letter?', 'routes/index-az.tsx'),
  route('sources', 'routes/sources.tsx'),
  route('sign-in/*', 'routes/sign-in.tsx'),
  route('sign-up/*', 'routes/sign-up.tsx'),
  route('account', 'routes/account.tsx'),
  route('account/do', 'routes/account-do.ts'),
  route('__fake/sign-in', 'routes/fake-sign-in.ts'),
  route('__fake/sign-out', 'routes/fake-sign-out.ts'),
  route('sitemap.xml', 'routes/sitemap.ts'),
  route('*', 'routes/not-found.tsx'),
] satisfies RouteConfig;
