import { src } from '../define';

// No parser and no pull. Checked 24 Nov 2026: https://transform.shadowserver.org/api2/ answers
// `401 Invalid API key or HMAC` without a key and a per-request HMAC signature, and no public feed was found.
// `CredentialName` does not cover an API key plus HMAC signing.
export default src('shadowserver', 'Shadowserver', 'Exposure statistics', 'since', 'daily', 'ask');
