import { NotImplementedError } from '@ti/core/errors';
import type { PatternContext, PatternResult } from './types';

export async function check(_ctx: PatternContext): Promise<'unchanged' | 'changed'> {
  throw new NotImplementedError('pattern fingerprint check');
}

export async function fetch(_ctx: PatternContext): Promise<PatternResult> {
  throw new NotImplementedError('pattern fingerprint fetch');
}
