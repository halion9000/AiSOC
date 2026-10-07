/**
 * Which push-service endpoints a subscription may name.
 *
 * `web-push` POSTs to whatever `endpoint` URL a subscription carries, and the subscription keys are chosen by whoever subscribes. An
 * unrestricted endpoint is therefore (a) a server-side request primitive aimed at anything this service can reach and (b) a way to
 * route a tenant's notification content to a destination of the subscriber's choosing. Real browsers always use their vendor's push
 * service, so we require https on a known push-service host and refuse everything else. Operators with a custom push gateway can
 * extend the list with AISOC_PUSH_ENDPOINT_HOSTS (comma-separated domains; subdomains match).
 */
const DEFAULT_PUSH_HOSTS = [
  'fcm.googleapis.com', // Chrome, Edge, Opera, Samsung Internet, Brave
  'android.googleapis.com',
  'push.services.mozilla.com', // Firefox (updates.push.services.mozilla.com)
  'notify.windows.com', // Edge/Windows (*.notify.windows.com)
  'push.apple.com', // Safari (web.push.apple.com)
];

const MAX_ENDPOINT_LENGTH = 2048;

export function allowedPushHosts(extra: string | undefined = process.env.AISOC_PUSH_ENDPOINT_HOSTS): string[] {
  const more = (extra || '')
    .split(',')
    .map((h) => h.trim().toLowerCase().replace(/^\.+/, ''))
    .filter(Boolean);
  return [...DEFAULT_PUSH_HOSTS, ...more];
}

function isIpLiteral(hostname: string): boolean {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(hostname) || hostname.includes(':') || hostname.startsWith('[');
}

/** Returns the parsed URL, or throws an Error whose message is safe to show the caller. */
export function assertPushEndpointAllowed(endpoint: unknown, hosts: string[] = allowedPushHosts()): URL {
  if (typeof endpoint !== 'string' || endpoint.length === 0 || endpoint.length > MAX_ENDPOINT_LENGTH) {
    throw new Error('subscription endpoint is invalid');
  }
  let url: URL;
  try {
    url = new URL(endpoint);
  } catch {
    throw new Error('subscription endpoint is invalid');
  }
  if (url.protocol !== 'https:') throw new Error('subscription endpoint must use https');
  if (url.username || url.password) throw new Error('subscription endpoint must not contain credentials');
  if (url.port && url.port !== '443') throw new Error('subscription endpoint must use the default https port');
  const host = url.hostname.toLowerCase().replace(/\.$/, '');
  if (!host || isIpLiteral(host)) throw new Error('subscription endpoint must be a push service host name');
  if (!hosts.some((allowed) => host === allowed || host.endsWith(`.${allowed}`))) {
    throw new Error('subscription endpoint is not a recognised push service');
  }
  return url;
}
