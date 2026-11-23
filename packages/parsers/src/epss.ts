import { NotImplementedError } from '@ti/core/errors';
import type { ParsedRecord } from '@ti/core/types';

export function parse(_input: unknown): ParsedRecord[] {
  throw new NotImplementedError('parser epss');
}
