import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';

import { allowedPushHosts, assertPushEndpointAllowed } from '../src/push-endpoint';

const ok = (endpoint: string, hosts?: string[]) => assertPushEndpointAllowed(endpoint, hosts);

test('real browsers push services are accepted', () => {
  for (const endpoint of [
    'https://fcm.googleapis.com/fcm/send/abc123',
    'https://updates.push.services.mozilla.com/wpush/v2/gAAAA',
    'https://wns2-par02p.notify.windows.com/w/?token=abc',
    'https://web.push.apple.com/QGxyz',
    'https://FCM.GoogleAPIs.com/fcm/send/x',
    'https://fcm.googleapis.com./fcm/send/x',
    'https://fcm.googleapis.com:443/fcm/send/x',
  ]) {
    assert.doesNotThrow(() => ok(endpoint), endpoint);
  }
});

test('plain http, other schemes, and malformed values are refused', () => {
  for (const endpoint of ['http://fcm.googleapis.com/x', 'ftp://fcm.googleapis.com/x', 'file:///etc/passwd', 'javascript:alert(1)', 'data:text/plain,hi', 'not a url', '', '//fcm.googleapis.com/x']) {
    assert.throws(() => ok(endpoint), /endpoint/, endpoint);
  }
  for (const bad of [undefined, null, 42, {}, [], true]) assert.throws(() => assertPushEndpointAllowed(bad), /invalid/);
  assert.throws(() => ok(`https://fcm.googleapis.com/${'a'.repeat(2100)}`), /invalid/);
});

test('internal and metadata addresses (the request-forgery targets) are refused', () => {
  for (const endpoint of [
    'https://127.0.0.1/x', 'https://10.0.0.5/x', 'https://169.254.169.254/latest/meta-data', 'https://192.168.1.1/x', 'https://[::1]/x', 'https://[fd00::1]/x',
    'https://localhost/x', 'https://redis/x', 'https://postgres:5432/x', 'https://api/x', 'https://kafka.internal/x', 'https://2130706433/x',
  ]) {
    assert.throws(() => ok(endpoint), /endpoint/, endpoint);
  }
});

test('look-alike hosts and URL tricks do not pass', () => {
  for (const endpoint of [
    'https://fcm.googleapis.com.evil.com/x', 'https://evilfcm.googleapis.com.attacker.net/x', 'https://notfcm.googleapis.com.evil.io/x',
    'https://fcm.googleapis.com@evil.com/x', 'https://fcm.googleapis.com:pw@evil.com/x', 'https://evil.com/fcm.googleapis.com', 'https://evil.com/?fcm.googleapis.com',
    'https://evilfcm.googleapis.com/x', 'https://xnotify.windows.com/x', 'https://notpush.apple.com/x', 'https://evil.com#fcm.googleapis.com', 'https://evil.com\\@fcm.googleapis.com', 'https://googleapis.com/x', 'https://push.apple.com.evil.com/x',
  ]) {
    assert.throws(() => ok(endpoint), /endpoint/, endpoint);
  }
  assert.throws(() => ok('https://user:pass@fcm.googleapis.com/x'), /credentials/);
  assert.throws(() => ok('https://fcm.googleapis.com:8443/x'), /port/);
});

test('an operator can extend the list for a custom push gateway, and only for that domain', () => {
  const hosts = allowedPushHosts('push.corp.example, .Other.Example ,');
  assert.doesNotThrow(() => ok('https://push.corp.example/x', hosts));
  assert.doesNotThrow(() => ok('https://a.b.other.example/x', hosts));
  assert.throws(() => ok('https://corp.example/x', hosts));
  assert.throws(() => ok('https://evilpush.corp.example.attacker.net/x', hosts));
  assert.throws(() => ok('https://push.corp.example/x'), /recognised/, 'the default list is unchanged');
});

test('the subscribe path really calls the validator before storing anything', () => {
  const src = fs.readFileSync(path.join(__dirname, '..', 'src', 'push.ts'), 'utf8');
  const upsert = src.slice(src.indexOf('async upsertSubscription'));
  assert.ok(upsert.indexOf('assertPushEndpointAllowed(sub.endpoint)') > 0, 'upsertSubscription must validate the endpoint');
  assert.ok(upsert.indexOf('assertPushEndpointAllowed(sub.endpoint)') < upsert.indexOf('hashEndpoint(sub.endpoint)'), 'validation must come before the subscription is stored');
});
