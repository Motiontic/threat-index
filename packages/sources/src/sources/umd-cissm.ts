import { src } from '../define';

// No parser, no pull. cissm.umd.edu now redirects to gpi.umd.edu/cissm and the database page answers 404; the data
// was a dashboard with downloads on request, so there is no public feed. See fixtures/umd-cissm/SOURCE.md.
export default src('umd-cissm', 'UMD CISSM', 'Cyber events database', 'heavy', 'monthly', 'ask', {
  heavy: true,
});
