import assert from 'node:assert/strict';
import test from 'node:test';
import webpush from 'web-push';

import { PushManager } from '../src/push';

// A minimal in-memory Redis with just the commands PushManager uses (get, set, smembers, and a multi() pipeline of set/sadd/srem/expire/del).
class FakeRedis {
  kv = new Map<string, string>();
  sets = new Map<string, Set<string>>();
  async get(k: string) { return this.kv.get(k) ?? null; }
  async set(k: string, v: string) { this.kv.set(k, v); return 'OK'; }
  async smembers(k: string) { return [...(this.sets.get(k) ?? [])]; }
  members(k: string) { return [...(this.sets.get(k) ?? [])]; }
  multi() {
    const ops: Array<() => void> = [];
    const p = {
      set: (k: string, v: string) => { ops.push(() => this.kv.set(k, v)); return p; },
      del: (k: string) => { ops.push(() => this.kv.delete(k)); return p; },
      sadd: (k: string, m: string) => { ops.push(() => { (this.sets.get(k) ?? this.sets.set(k, new Set()).get(k)!).add(m); }); return p; },
      srem: (k: string, m: string) => { ops.push(() => { this.sets.get(k)?.delete(m); }); return p; },
      expire: () => p,
      exec: async () => { ops.forEach((o) => o()); return []; },
    };
    return p;
  }
}

const logger: any = { info() {}, warn() {}, error() {}, debug() {}, child() { return logger; } };
const vapid = webpush.generateVAPIDKeys();
function setup() {
  const redis = new FakeRedis();
  const mgr = new PushManager({ redis: redis as any, logger, vapidPublicKey: vapid.publicKey, vapidPrivateKey: vapid.privateKey, vapidSubject: 'mailto:ops@example.com' });
  return { redis, mgr };
}
const sub = (name: string) => ({ endpoint: `https://fcm.googleapis.com/fcm/send/${name}`, keys: { p256dh: `p-${name}`, auth: `a-${name}` } });
const res = () => { const r: any = { code: 200, body: undefined, status(c: number) { r.code = c; return r; }, json(b: unknown) { r.body = b; return r; } }; return r; };
const req = (headers: Record<string, string>, body: unknown): any => ({ headers, body, query: {} });
const A = 'tenant-a', B = 'tenant-b';

test('the normal path still works: subscribe, resolve for the tenant, the user and the topic, unsubscribe', async () => {
  const { mgr } = setup();
  await mgr.upsertSubscription(A, 'alice', { subscription: sub('d1'), topics: ['p0_alert'] } as any);
  assert.equal((await mgr.resolveSubscriptions({ tenant_id: A })).length, 1);
  assert.equal((await mgr.resolveSubscriptions({ tenant_id: A, user_ids: ['alice'] })).length, 1);
  assert.equal((await mgr.resolveSubscriptions({ tenant_id: A, topic: 'p0_alert' })).length, 1);
  assert.equal((await mgr.resolveSubscriptions({ tenant_id: A, user_ids: ['bob'] })).length, 0);
  assert.equal(await mgr.removeSubscription(A, sub('d1').endpoint, 'alice'), true);
  assert.equal((await mgr.resolveSubscriptions({ tenant_id: A })).length, 0);
});

test('subscribe: the VERIFIED header user wins over a user_id in the body', async () => {
  const { mgr } = setup();
  const r = res();
  await mgr.subscribeHandler(req({ 'x-tenant-id': A, 'x-user-id': 'mallory' }, { subscription: sub('m1'), user_id: 'victim' }), r);
  assert.equal(r.code, 201);
  assert.equal((await mgr.resolveSubscriptions({ tenant_id: A, user_ids: ['victim'] })).length, 0, 'the device must NOT be registered as the victim');
  assert.equal((await mgr.resolveSubscriptions({ tenant_id: A, user_ids: ['mallory'] })).length, 1);
});

test('subscribe: an internal caller that sends no header can still name the user in the body', async () => {
  const { mgr } = setup();
  await mgr.subscribeHandler(req({ 'x-tenant-id': A }, { subscription: sub('i1'), user_id: 'carol' }), res());
  assert.equal((await mgr.resolveSubscriptions({ tenant_id: A, user_ids: ['carol'] })).length, 1);
});

test('unsubscribe: another tenant knowing the endpoint cannot remove it', async () => {
  const { mgr } = setup();
  await mgr.upsertSubscription(A, 'alice', { subscription: sub('d2') } as any);
  const r = res();
  await mgr.unsubscribeHandler(req({ 'x-tenant-id': B, 'x-user-id': 'eve' }, { endpoint: sub('d2').endpoint }), r);
  assert.deepEqual(r.body, { removed: false });
  assert.equal((await mgr.resolveSubscriptions({ tenant_id: A })).length, 1, 'tenant A still has its subscription');
});

test('unsubscribe: another USER of the same tenant cannot remove it; the owner can', async () => {
  const { mgr } = setup();
  await mgr.upsertSubscription(A, 'alice', { subscription: sub('d3') } as any);
  const other = res();
  await mgr.unsubscribeHandler(req({ 'x-tenant-id': A, 'x-user-id': 'bob' }, { endpoint: sub('d3').endpoint }), other);
  assert.deepEqual(other.body, { removed: false });
  assert.equal((await mgr.resolveSubscriptions({ tenant_id: A, user_ids: ['alice'] })).length, 1);
  const owner = res();
  await mgr.unsubscribeHandler(req({ 'x-tenant-id': A, 'x-user-id': 'alice' }, { endpoint: sub('d3').endpoint }), owner);
  assert.deepEqual(owner.body, { removed: true });
});

test('unsubscribe: the tenant check holds for the pruning path too (removeSubscriptionById)', async () => {
  const { mgr } = setup();
  const rec = await mgr.upsertSubscription(A, 'alice', { subscription: sub('d4') } as any);
  assert.equal(await mgr.removeSubscriptionById(B, rec.id), false);
  assert.equal(await mgr.removeSubscriptionById(A, rec.id), true);
});

test('delivery: a record whose tenant does not match the target is never returned, even if an index set lists it', async () => {
  const { mgr, redis } = setup();
  const rec = await mgr.upsertSubscription(B, 'bob', { subscription: sub('d5') } as any);
  redis.sets.set('aisoc:push:tenant:' + A, new Set([rec.id])); // a stale / corrupted index entry pointing tenant A at tenant B's device
  assert.equal((await mgr.resolveSubscriptions({ tenant_id: A })).length, 0);
  assert.equal((await mgr.resolveSubscriptions({ tenant_id: B })).length, 1);
});

test('delivery: a user target only returns that user\'s records', async () => {
  const { mgr, redis } = setup();
  const rec = await mgr.upsertSubscription(A, 'bob', { subscription: sub('d6') } as any);
  redis.sets.set('aisoc:push:user:' + A + ':alice', new Set([rec.id])); // alice's index wrongly lists bob's device
  assert.equal((await mgr.resolveSubscriptions({ tenant_id: A, user_ids: ['alice'] })).length, 0);
});

test('re-subscribing an endpoint under ANOTHER tenant removes it from the old tenant, user and topic sets', async () => {
  const { mgr, redis } = setup();
  const rec = await mgr.upsertSubscription(A, 'alice', { subscription: sub('d7'), topics: ['p0_alert'] } as any);
  await mgr.upsertSubscription(B, 'bob', { subscription: sub('d7'), topics: ['p0_alert'] } as any);
  assert.deepEqual(redis.members('aisoc:push:tenant:' + A), []);
  assert.deepEqual(redis.members('aisoc:push:user:' + A + ':alice'), []);
  assert.deepEqual(redis.members('aisoc:push:topic:' + A + ':p0_alert'), []);
  assert.equal((await mgr.resolveSubscriptions({ tenant_id: A })).length, 0, 'tenant A no longer reaches this device');
  assert.deepEqual((await mgr.resolveSubscriptions({ tenant_id: B })).map((r) => r.id), [rec.id]);
});

test('re-subscribing under another USER of the same tenant moves the device off the old user', async () => {
  const { mgr, redis } = setup();
  await mgr.upsertSubscription(A, 'alice', { subscription: sub('d8') } as any);
  await mgr.upsertSubscription(A, 'bob', { subscription: sub('d8') } as any);
  assert.equal((await mgr.resolveSubscriptions({ tenant_id: A, user_ids: ['alice'] })).length, 0);
  assert.equal((await mgr.resolveSubscriptions({ tenant_id: A, user_ids: ['bob'] })).length, 1);
  // The delivery filter would hide a stale entry, so look at the index itself: alice's set must no longer list the device.
  assert.deepEqual(redis.members('aisoc:push:user:' + A + ':alice'), []);
  assert.equal(redis.members('aisoc:push:user:' + A + ':bob').length, 1);
});

test('re-subscribing the SAME tenant and user with different topics still prunes the old topics (unchanged behaviour)', async () => {
  const { mgr, redis } = setup();
  await mgr.upsertSubscription(A, 'alice', { subscription: sub('d9'), topics: ['p0_alert', 'oncall_handoff'] } as any);
  await mgr.upsertSubscription(A, 'alice', { subscription: sub('d9'), topics: ['p0_alert'] } as any);
  assert.deepEqual(redis.members('aisoc:push:topic:' + A + ':oncall_handoff'), []);
  assert.equal(redis.members('aisoc:push:topic:' + A + ':p0_alert').length, 1);
  assert.equal(redis.members('aisoc:push:tenant:' + A).length, 1, 'not duplicated');
});
