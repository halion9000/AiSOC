import { ApiError } from '@/lib/api';

/**
 * Why a copilot call failed, in words an analyst can act on. The backend now answers an unanswerable chat with HTTP 503 and a `detail` saying why (for example "no
 * language-model API key is configured for the copilot"); the UIs used to swallow the error and say only that the AI backend was "unreachable", which is wrong when it was
 * reached and said no.
 */
export function copilotFailureReason(err: unknown): string {
  if (err instanceof ApiError) {
    try {
      const detail = JSON.parse(err.body)?.detail;
      if (typeof detail === 'string' && detail) return detail.replace(/[.\s]+$/, ''); // callers end the sentence themselves
    } catch {
      /* the body was not JSON */
    }
    return err.status === 0 ? 'the AiSOC API could not be reached' : `the AiSOC API answered ${err.status}`;
  }
  return err instanceof Error && err.message ? err.message : 'the AiSOC API could not be reached';
}

export function copilotFailureText(err: unknown): string {
  return `The copilot could not answer: ${copilotFailureReason(err)}`;
}
