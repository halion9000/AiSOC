import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const responder = vi.hoisted(() => ({ getPublicKey: vi.fn(), subscribe: vi.fn(), unsubscribe: vi.fn() }));
vi.mock('./api', () => ({ responderApi: responder }));

import {
  getServiceWorkerStatus,
  isStandalone,
  listQueuedApprovals,
  onInstallPromptAvailable,
  queueApproval,
  registerServiceWorker,
  requestNotificationPermission,
  showInstallPrompt,
  subscribeToPush,
  unsubscribeFromPush,
  urlBase64ToUint8Array,
} from './pwa';

const nav = navigator as unknown as Record<string, unknown>;
const had = (k: string) => Object.prototype.hasOwnProperty.call(nav, k);
const saved: Record<string, PropertyDescriptor | undefined> = {};
function setNav(key: string, value: unknown) {
  if (!(key in saved)) saved[key] = Object.getOwnPropertyDescriptor(navigator, key);
  Object.defineProperty(navigator, key, { value, configurable: true });
}
function removeNav(key: string) {
  if (!(key in saved)) saved[key] = Object.getOwnPropertyDescriptor(navigator, key);
  delete nav[key];
  if (key in navigator) Object.defineProperty(navigator, key, { value: undefined, configurable: true });
}

beforeEach(() => {
  responder.getPublicKey.mockReset();
  responder.subscribe.mockReset().mockResolvedValue({});
  responder.unsubscribe.mockReset().mockResolvedValue({});
});
afterEach(() => {
  for (const [k, d] of Object.entries(saved)) {
    if (d) Object.defineProperty(navigator, k, d);
    else delete nav[k];
  }
  for (const k of Object.keys(saved)) delete saved[k];
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
  void had;
});

describe('urlBase64ToUint8Array', () => {
  it('decodes URL-safe base64 with the padding left off', () => {
    // "hello" is aGVsbG8= in plain base64.
    expect(Array.from(urlBase64ToUint8Array('aGVsbG8'))).toEqual([104, 101, 108, 108, 111]);
    expect(Array.from(urlBase64ToUint8Array('aGVsbG8='))).toEqual([104, 101, 108, 108, 111]);
  });
  it('turns - and _ back into + and /', () => {
    // bytes fb ff fe are "+//+" in plain base64 and "-__-" URL-safe.
    expect(Array.from(urlBase64ToUint8Array('-__-'))).toEqual([0xfb, 0xff, 0xfe]);
  });
  it('an empty key is an empty array', () => {
    expect(urlBase64ToUint8Array('').length).toBe(0);
  });
  it('decodes a real-length VAPID key (65 bytes) to 65 bytes', () => {
    const key = Buffer.from(Uint8Array.from({ length: 65 }, (_, i) => i * 3)).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    const out = urlBase64ToUint8Array(key);
    expect(out.length).toBe(65);
    expect(out[64]).toBe(192);
  });
});

describe('registerServiceWorker', () => {
  it('returns null when the browser has no service workers', async () => {
    removeNav('serviceWorker');
    expect(await registerServiceWorker()).toBeNull();
  });

  it('registers /sw.js at the root without letting the browser cache the script, and asks for an update when the tab comes back', async () => {
    const update = vi.fn().mockResolvedValue(undefined);
    const register = vi.fn().mockResolvedValue({ update });
    setNav('serviceWorker', { register });
    const reg = await registerServiceWorker();
    expect(register).toHaveBeenCalledWith('/sw.js', { scope: '/', updateViaCache: 'none' });
    expect(reg).toEqual({ update });
    Object.defineProperty(document, 'visibilityState', { value: 'visible', configurable: true });
    document.dispatchEvent(new Event('visibilitychange'));
    expect(update).toHaveBeenCalledTimes(1);
  });

  it('a failed registration is a null and a warning, not an error', async () => {
    setNav('serviceWorker', { register: vi.fn().mockRejectedValue(new Error('blocked')) });
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    expect(await registerServiceWorker()).toBeNull();
    expect(warn).toHaveBeenCalled();
  });
});

describe('getServiceWorkerStatus', () => {
  it('says unsupported, not registered, or active with its scope', async () => {
    removeNav('serviceWorker');
    expect(await getServiceWorkerStatus()).toEqual({ supported: false, registered: false, active: false });
    setNav('serviceWorker', { getRegistration: vi.fn().mockResolvedValue(undefined) });
    expect(await getServiceWorkerStatus()).toEqual({ supported: true, registered: false, active: false });
    setNav('serviceWorker', { getRegistration: vi.fn().mockResolvedValue({ scope: '/app/', active: { scriptURL: 'http://x/sw.js' } }) });
    expect(await getServiceWorkerStatus()).toEqual({ supported: true, registered: true, active: true, scope: '/app/', scriptUrl: 'http://x/sw.js' });
    setNav('serviceWorker', { getRegistration: vi.fn().mockResolvedValue({ scope: '/', active: null }) });
    expect((await getServiceWorkerStatus()).active).toBe(false);
  });
});

describe('requestNotificationPermission', () => {
  const stubNotification = (permission: NotificationPermission, ask = vi.fn().mockResolvedValue('granted')) => {
    const N = Object.assign(function () {}, { permission, requestPermission: ask });
    vi.stubGlobal('Notification', N);
    Object.defineProperty(window, 'PushManager', { value: function () {}, configurable: true });
    return ask;
  };
  afterEach(() => {
    delete (window as unknown as Record<string, unknown>).PushManager;
  });

  it('reports unsupported when the browser has no notifications or no push', async () => {
    vi.stubGlobal('Notification', undefined);
    expect(await requestNotificationPermission()).toEqual({ state: 'denied', supported: false });
    vi.stubGlobal('Notification', Object.assign(function () {}, { permission: 'default' }));
    delete (window as unknown as Record<string, unknown>).PushManager;
    expect(await requestNotificationPermission()).toEqual({ state: 'denied', supported: false });
  });
  it('does not ask again when the answer is already known', async () => {
    const ask = stubNotification('granted');
    expect(await requestNotificationPermission()).toEqual({ state: 'granted', supported: true });
    stubNotification('denied', ask);
    expect(await requestNotificationPermission()).toEqual({ state: 'denied', supported: true });
    expect(ask).not.toHaveBeenCalled();
  });
  it('asks when it has not been decided, and returns the answer', async () => {
    const ask = stubNotification('default', vi.fn().mockResolvedValue('denied'));
    expect(await requestNotificationPermission()).toEqual({ state: 'denied', supported: true });
    expect(ask).toHaveBeenCalledTimes(1);
  });
});

describe('subscribeToPush', () => {
  const sub = (over: Record<string, unknown> = {}) => ({
    toJSON: () => ({ endpoint: 'https://push.example/abc', keys: { p256dh: 'P', auth: 'A' }, expirationTime: null, ...over }),
  });
  const withWorker = (pushManager: unknown) => setNav('serviceWorker', { ready: Promise.resolve({ pushManager }) });

  it('returns null without service workers, or when the browser has no push manager', async () => {
    removeNav('serviceWorker');
    expect(await subscribeToPush()).toBeNull();
    withWorker(undefined);
    expect(await subscribeToPush()).toBeNull();
  });

  it('an existing subscription is re-registered with the gateway (default topics) and returned, without asking the server for a key', async () => {
    const existing = sub();
    withWorker({ getSubscription: vi.fn().mockResolvedValue(existing) });
    expect(await subscribeToPush()).toBe(existing);
    expect(responder.getPublicKey).not.toHaveBeenCalled();
    const body = responder.subscribe.mock.calls[0][0];
    expect(body.subscription).toEqual({ endpoint: 'https://push.example/abc', keys: { p256dh: 'P', auth: 'A' }, expirationTime: null });
    expect(body.topics).toEqual(['p0_alert', 'agent_approval', 'oncall_handoff']);
  });

  it('a new subscription uses the server\'s key, is visible-only, and is registered with the chosen topics', async () => {
    const created = sub();
    const subscribe = vi.fn().mockResolvedValue(created);
    withWorker({ getSubscription: vi.fn().mockResolvedValue(null), subscribe });
    responder.getPublicKey.mockResolvedValue({ enabled: true, public_key: 'aGVsbG8' });
    expect(await subscribeToPush({ topics: ['only_this'] })).toBe(created);
    const args = subscribe.mock.calls[0][0];
    expect(args.userVisibleOnly).toBe(true);
    expect(Array.from(args.applicationServerKey as Uint8Array)).toEqual([104, 101, 108, 108, 111]);
    expect(responder.subscribe.mock.calls[0][0].topics).toEqual(['only_this']);
  });

  it('when the server has push switched off nothing is subscribed', async () => {
    const subscribe = vi.fn();
    withWorker({ getSubscription: vi.fn().mockResolvedValue(null), subscribe });
    vi.spyOn(console, 'info').mockImplementation(() => {});
    for (const answer of [{ enabled: false, public_key: 'k' }, { enabled: true, public_key: '' }]) {
      responder.getPublicKey.mockResolvedValue(answer);
      expect(await subscribeToPush()).toBeNull();
    }
    expect(subscribe).not.toHaveBeenCalled();
    expect(responder.subscribe).not.toHaveBeenCalled();
  });

  it('a subscription with no keys is refused rather than sent half-empty', async () => {
    withWorker({ getSubscription: vi.fn().mockResolvedValue(sub({ keys: {} })) });
    await expect(subscribeToPush()).rejects.toThrow(/missing endpoint\/keys/);
    expect(responder.subscribe).not.toHaveBeenCalled();
  });
});

describe('unsubscribeFromPush', () => {
  it('is false when there is nothing to unsubscribe from', async () => {
    removeNav('serviceWorker');
    expect(await unsubscribeFromPush()).toBe(false);
    setNav('serviceWorker', { getRegistration: vi.fn().mockResolvedValue(undefined) });
    expect(await unsubscribeFromPush()).toBe(false);
    setNav('serviceWorker', { getRegistration: vi.fn().mockResolvedValue({ pushManager: { getSubscription: vi.fn().mockResolvedValue(null) } }) });
    expect(await unsubscribeFromPush()).toBe(false);
  });
  it('tells the server and unsubscribes the browser, and still unsubscribes if the server call fails', async () => {
    const unsubscribe = vi.fn().mockResolvedValue(true);
    setNav('serviceWorker', { getRegistration: vi.fn().mockResolvedValue({ pushManager: { getSubscription: vi.fn().mockResolvedValue({ endpoint: 'https://push.example/x', unsubscribe }) } }) });
    expect(await unsubscribeFromPush()).toBe(true);
    expect(responder.unsubscribe).toHaveBeenCalledWith('https://push.example/x');
    responder.unsubscribe.mockRejectedValue(new Error('offline'));
    expect(await unsubscribeFromPush()).toBe(true);
    expect(unsubscribe).toHaveBeenCalledTimes(2);
  });
});

describe('isStandalone', () => {
  it('is true in an installed app (display mode or the older Safari flag) and false in a tab', () => {
    window.matchMedia = vi.fn().mockReturnValue({ matches: false }) as never;
    expect(isStandalone()).toBe(false);
    window.matchMedia = vi.fn().mockReturnValue({ matches: true }) as never;
    expect(isStandalone()).toBe(true);
    window.matchMedia = vi.fn().mockReturnValue({ matches: false }) as never;
    setNav('standalone', true);
    expect(isStandalone()).toBe(true);
  });
});

describe('the install prompt', () => {
  const offer = () => {
    const e = Object.assign(new Event('beforeinstallprompt', { cancelable: true }), { prompt: vi.fn().mockResolvedValue(undefined), userChoice: Promise.resolve({ outcome: 'accepted' as const, platform: 'web' }) });
    window.dispatchEvent(e);
    return e;
  };
  it('says unavailable until the browser offers it, then offers it once and forgets it after use', async () => {
    expect(await showInstallPrompt()).toBe('unavailable');
    const seen: boolean[] = [];
    const off = onInstallPromptAvailable((a) => seen.push(a));
    expect(seen).toEqual([false]);
    const event = offer();
    expect(event.defaultPrevented).toBe(true);
    expect(seen).toEqual([false, true]);
    expect(await showInstallPrompt()).toBe('accepted');
    expect(event.prompt).toHaveBeenCalledTimes(1);
    expect(seen).toEqual([false, true, false]);
    expect(await showInstallPrompt()).toBe('unavailable');
    off();
    offer();
    expect(seen).toEqual([false, true, false]);
    window.dispatchEvent(new Event('appinstalled'));
  });
  it('once the app is installed the offer is withdrawn', () => {
    offer();
    const seen: boolean[] = [];
    const off = onInstallPromptAvailable((a) => seen.push(a));
    window.dispatchEvent(new Event('appinstalled'));
    expect(seen).toEqual([true, false]);
    off();
  });
});

describe('the offline approval queue', () => {
  it('without IndexedDB, queueing is an error and listing is empty', async () => {
    vi.stubGlobal('indexedDB', undefined);
    await expect(queueApproval({ approval_id: 'a1', decision: 'approve' })).rejects.toThrow(/IndexedDB not available/);
    expect(await listQueuedApprovals()).toEqual([]);
  });

  /** The smallest IndexedDB that the queue's code path needs. */
  function fakeIndexedDb() {
    const rows = new Map<string, unknown>();
    const stores = new Set<string>();
    const db = {
      objectStoreNames: { contains: (n: string) => stores.has(n) },
      createObjectStore: (n: string) => void stores.add(n),
      transaction: () => {
        const tx: Record<string, unknown> = {};
        tx.objectStore = () => ({
          put: (r: { id: string }) => { rows.set(r.id, r); setTimeout(() => (tx.oncomplete as () => void)?.()); },
          getAll: () => { const req: Record<string, unknown> = {}; setTimeout(() => { req.result = [...rows.values()]; (req.onsuccess as () => void)?.(); }); return req; },
        });
        return tx;
      },
    };
    vi.stubGlobal('indexedDB', {
      open: () => {
        const req: Record<string, unknown> = { result: db };
        setTimeout(() => { (req.onupgradeneeded as () => void)?.(); (req.onsuccess as () => void)?.(); });
        return req;
      },
    });
    return rows;
  }

  it('stores the decision with an id and a time, and lists it back', async () => {
    const rows = fakeIndexedDb();
    removeNav('serviceWorker');
    const id = await queueApproval({ approval_id: 'ap-7', decision: 'deny', reason: 'not me' });
    expect(id.startsWith('ap-7:')).toBe(true);
    const stored = rows.get(id) as Record<string, unknown>;
    expect(stored).toMatchObject({ id, approval_id: 'ap-7', decision: 'deny', reason: 'not me' });
    expect(typeof stored.queued_at).toBe('number');
    expect((await listQueuedApprovals()).map((r) => r.approval_id)).toEqual(['ap-7']);
  });

  it('asks the service worker to replay it when background sync exists, and carries on when that is refused', async () => {
    fakeIndexedDb();
    const register = vi.fn().mockRejectedValue(new Error('no sync'));
    setNav('serviceWorker', { ready: Promise.resolve({ sync: { register } }) });
    (window as unknown as Record<string, unknown>).SyncManager = function () {};
    try {
      await expect(queueApproval({ approval_id: 'ap-8', decision: 'approve' })).resolves.toMatch(/^ap-8:/);
      expect(register).toHaveBeenCalledWith('approval-replay');
    } finally {
      delete (window as unknown as Record<string, unknown>).SyncManager;
    }
  });
});
