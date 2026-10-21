/** What the API says about a connector's health, as the dashboard reads it. The API sends the connector's health: healthy, degraded, unhealthy or unknown ("active" is the fallback for a connector with none). */
export type SourceTone = 'ok' | 'warning' | 'down' | 'idle';

export function sourceTone(status: string | null | undefined): SourceTone {
  switch ((status ?? '').toLowerCase()) {
    case 'active':
    case 'healthy':
    case 'ok':
      return 'ok';
    case 'degraded':
    case 'warning':
      return 'warning';
    case 'unhealthy':
    case 'error':
    case 'failed':
      return 'down';
    default:
      return 'idle';
  }
}

/** A source counts as connected when it is working, even if it reported a warning. One that is failing or has never reported does not. */
export function isConnected(status: string | null | undefined): boolean {
  const tone = sourceTone(status);
  return tone === 'ok' || tone === 'warning';
}

export function connectedCount(sources: ReadonlyArray<{ status: string }>): number {
  return sources.filter((s) => isConnected(s.status)).length;
}

export const TONE_DOT: Record<SourceTone, string> = {
  ok: 'bg-green-500',
  warning: 'bg-amber-500',
  down: 'bg-red-500',
  idle: 'bg-gray-500',
};
