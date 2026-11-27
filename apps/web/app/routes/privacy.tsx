import { env } from 'cloudflare:workers';
import { PRODUCT_SHORT } from '@ti/core/brand';
import { data } from 'react-router';
import { PrivacyPage } from '../components/privacy-page';
import { privacyBlocked } from '../lib/privacy';
import { LAST_UPDATED, PRIVACY_SECTIONS } from '../lib/privacy-content';
import { buildMeta, pageTitle } from '../lib/seo';
import { siteOrigin } from '../lib/site.server';
import type { Route } from './+types/privacy';

export function loader({ request }: Route.LoaderArgs) {
  // Unfinished owner decisions must never reach production.
  if (privacyBlocked(env.TI_ENV)) throw data(null, { status: 503 });
  return { origin: siteOrigin(request) };
}

export function meta({ loaderData }: Route.MetaArgs) {
  if (!loaderData) return [{ title: pageTitle('Privacy') }];
  return buildMeta({
    title: pageTitle('Privacy'),
    description: `What ${PRODUCT_SHORT} stores about you, why, for how long, and how to delete it.`,
    path: '/privacy',
    origin: loaderData.origin,
  });
}

export default PrivacyPage;
