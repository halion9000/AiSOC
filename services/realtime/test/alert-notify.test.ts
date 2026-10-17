/**
 * Which fused alerts page a responder, and the WebSocket connection rate limiter.
 *
 * Before: every fused message with severity critical/high pushed a notification, and about half the messages on the fused topic are DUPLICATE
 * (an alert already stored), so on-call was paged again for the same alert, sometimes with a deep link to a row that was never written
 * (persist_outcome failed/unavailable).
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { createRateLimiter, pushableAlert } from '../src/alert-notify';

const base = (over: Record<string, unknown> = {}) => ({
  fusion_decision: 'new_incident',
  persist_outcome: 'inserted',
  alert: { id: 'a-1', tenant_id: 't', severity: 'critical', title: 'Ransomware on DC01' },
  ...over,
});

test('a new critical alert is pushed with the P0 title and a deep link', () => {
  const p = pushableAlert(base());
  assert.ok(p);
  assert.equal(p.severity, 'critical');
  assert.equal(p.alertId, 'a-1');
  assert.match(p.title, /^P0 alert/);
});

test('a high alert is P1', () => {
  assert.match(pushableAlert(base({ alert: { id: 'a-2', severity: 'high', title: 't' } }))!.title, /^P1 alert/);
});

test('lower severities are not pushed', () => {
  for (const severity of ['medium', 'low', 'info', '']) {
    assert.equal(pushableAlert(base({ alert: { id: 'a', severity } })), null);
  }
});

test('a duplicate is not pushed again', () => {
  assert.equal(pushableAlert(base({ fusion_decision: 'duplicate' })), null);
  assert.equal(pushableAlert(base({ persist_outcome: 'duplicate' })), null);
});

test('an alert that was not stored is not pushed (its deep link would open nothing)', () => {
  assert.equal(pushableAlert(base({ persist_outcome: 'failed' })), null);
  assert.equal(pushableAlert(base({ persist_outcome: 'unavailable' })), null);
});

test('an envelope with no outcome fields (older producers) is still judged by severity', () => {
  assert.ok(pushableAlert({ alert: { id: 'a', severity: 'critical', title: 't' } }));
});

test('the rate limiter allows the limit then refuses, per key, and the window resets', () => {
  let now = 1_000;
  const limiter = createRateLimiter({ limit: 3, windowMs: 60_000, now: () => now });
  assert.deepEqual([1, 2, 3, 4].map(() => limiter.exceeded('1.1.1.1')), [false, false, false, true]);
  assert.equal(limiter.exceeded('2.2.2.2'), false);
  now += 60_001;
  assert.equal(limiter.exceeded('1.1.1.1'), false);
});

test('expired entries are pruned, so the map cannot grow without bound', () => {
  let now = 0;
  const limiter = createRateLimiter({ limit: 1, windowMs: 1_000, now: () => now });
  for (let i = 0; i < 500; i++) limiter.exceeded(`10.0.0.${i}`);
  assert.equal(limiter.size(), 500);
  now += 5_000;
  limiter.prune();
  assert.equal(limiter.size(), 0);
});
