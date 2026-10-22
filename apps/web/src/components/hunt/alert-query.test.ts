import { describe, expect, it } from 'vitest';
import { questionToAlertSearch as q } from './alert-query';

describe('questionToAlertSearch', () => {
  it('drops filler words, singularises, and turns a trailing "at <org>" into a client filter', () => {
    expect(q('any suspicious logins at live oak')).toBe('suspicious login client:"live oak"');
  });
  it('turns severity and status words into fields', () => {
    expect(q('show me high severity open alerts')).toBe('severity:high status:open');
  });
  it('keeps quoted phrases and ignores trailing punctuation', () => {
    expect(q('find "impossible travel" for jsmith@example.com?')).toBe('"impossible travel" jsmith@example.com');
  });
  it('is empty when nothing searchable remains', () => {
    expect(q('show me all of the alerts?')).toBe('');
    expect(q('   ')).toBe('');
  });
});
