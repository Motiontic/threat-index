import { src } from '../define';

// Left unwired: the list pages answer "Page Requested Currently Not available" to a plain GET and no RSS or JSON list
// was found (24 Nov 2026). Revisit when one exists.
export default src('cert-in', 'CERT-In', 'Indian government advisories', 'page', 'daily', 'ask');
