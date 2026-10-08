import { describe, expect, it } from 'vitest';
import { ApiError } from '@/lib/api';
import { copilotFailureReason, copilotFailureText } from './copilotFailure';

const api = (status: number, body: string) => new ApiError(`API ${status}`, status, body);

describe('copilotFailureReason', () => {
  it("uses the backend's own reason, without its trailing period", () => {
    const err = api(503, JSON.stringify({ detail: 'The copilot cannot answer right now: no language-model API key is configured for the copilot.' }));
    expect(copilotFailureReason(err)).toBe('The copilot cannot answer right now: no language-model API key is configured for the copilot');
  });

  it('falls back to the status when the body is not JSON or has no string detail', () => {
    expect(copilotFailureReason(api(502, '<html>Bad gateway</html>'))).toBe('the AiSOC API answered 502');
    expect(copilotFailureReason(api(422, JSON.stringify({ detail: [{ msg: 'x' }] })))).toBe('the AiSOC API answered 422');
    expect(copilotFailureReason(api(500, JSON.stringify({ detail: '' })))).toBe('the AiSOC API answered 500');
  });

  it('says the API could not be reached for a network error (status 0)', () => {
    expect(copilotFailureReason(api(0, ''))).toBe('the AiSOC API could not be reached');
  });

  it('uses a plain error message, and a safe fallback for anything else', () => {
    expect(copilotFailureReason(new Error('socket hang up'))).toBe('socket hang up');
    expect(copilotFailureReason(new Error(''))).toBe('the AiSOC API could not be reached');
    expect(copilotFailureReason('weird')).toBe('the AiSOC API could not be reached');
  });
});

describe('copilotFailureText', () => {
  it('states that the copilot could not answer, and why', () => {
    expect(copilotFailureText(api(503, JSON.stringify({ detail: 'no key.' })))).toBe('The copilot could not answer: no key');
  });
});
