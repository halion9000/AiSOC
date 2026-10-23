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
  it('does not repeat a word and keeps several quoted phrases', () => {
    expect(q('login login "bad actor" "bad actor" logins')).toBe('"bad actor" login');
  });
  it('treats a trailing organization of up to four words (after an optional the) as the client', () => {
    expect(q('failed logins for the hill country christian school')).toBe('failed login client:"hill country christian school"');
    expect(q('malware on pc-01')).toBe('malware pc-01'); // "on" is not an organization marker: a machine name stays a plain word
  });
  it('turns severity and status words anywhere in the question into fields, once each', () => {
    expect(q('open critical alerts that are high severity')).toBe('status:open severity:critical severity:high');
  });
  it('keeps host names, addresses and emails together as one word', () => {
    expect(q('what did jsmith@example.com do from 10.0.0.5')).toBe('jsmith@example.com 10.0.0.5');
  });
  it('is not confused by a trailing question mark, extra spaces or capitals', () => {
    expect(q('   Any   SUSPICIOUS   Logins??  ')).toBe('suspicious login');
  });
});
