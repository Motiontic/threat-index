import { index, type RouteConfig, route } from '@react-router/dev/routes';

export default [
  index('routes/home.tsx'),
  route('search', 'routes/search.tsx'),
  route('e/:id', 'routes/entry.tsx'),
  route('index/:letter?', 'routes/index-az.tsx'),
  route('sources', 'routes/sources.tsx'),
  route('account', 'routes/account.tsx'),
] satisfies RouteConfig;
