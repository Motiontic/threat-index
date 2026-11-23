import { src } from '../define';

// No parser, no pull. The list is published as a PDF timeline and the program page answers 403 (a bot challenge)
// to curl, so there is no machine-readable feed. See fixtures/csis/SOURCE.md.
export default src(
  'csis',
  'CSIS significant incidents',
  'Major incidents timeline',
  'heavy',
  'monthly',
  'ask',
  {
    heavy: true,
  },
);
