import { data } from 'react-router';

/** Catch-all: a 404 that still runs the root loader, so the error page knows the data mode. */
export async function loader() {
  throw data(null, { status: 404 });
}

export default function NotFound() {
  return null;
}
