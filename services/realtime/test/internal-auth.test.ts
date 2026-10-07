import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import test from 'node:test';

import express from 'express';

import { checkInternalToken, internalAuth, isDevelopmentEnv, presentedInternalToken } from '../src/internal-auth';

const TOKEN = 'realtime-internal-token-123';

async function withApp(options: Parameters<typeof internalAuth>[0], fn: (call: (headers?: Record<string, string>) => Promise<{ status: number; body: any }>) => Promise<void>) {
  const app = express();
  app.post('/guarded', internalAuth(options), (_req, res) => res.json({ reached: true }));
  const server = http.createServer(app);
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address() as { port: number };
  try {
    await fn(async (headers = {}) => {
      const r = await fetch(`http://127.0.0.1:${port}/guarded`, { method: 'POST', headers });
      return { status: r.status, body: await r.json() };
    });
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
}

const prod = { token: () => TOKEN, development: () => false };

test('no credentials is a 401 and the handler is never reached', async () => {
  await withApp(prod, async (call) => {
    const r = await call();
    assert.equal(r.status, 401);
    assert.equal(r.body.reached, undefined);
  });
});

test('the right token is accepted under either header name (agents and the API use different ones)', async () => {
  await withApp(prod, async (call) => {
    assert.equal((await call({ 'x-internal-token': TOKEN })).status, 200);
    assert.equal((await call({ 'X-AiSOC-Internal-Token': TOKEN })).status, 200);
  });
});

test('only the exact token is accepted: longer, shorter, prefix, empty, and wrong-case all fail without crashing', async () => {
  await withApp(prod, async (call) => {
    for (const bad of [`${TOKEN}x`, TOKEN.slice(0, -1), TOKEN.slice(0, 5), 'x'.repeat(500), TOKEN.toUpperCase(), ' ', `Bearer ${TOKEN}`]) {
      assert.equal((await call({ 'x-internal-token': bad })).status, 401, JSON.stringify(bad));
    }
    assert.equal((await call({ 'x-internal-token': '' })).status, 401);
  });
});

test('with no token configured, anything but development answers 503 even if a token is presented (fail closed)', async () => {
  await withApp({ token: () => '', development: () => false }, async (call) => {
    for (const headers of [{}, { 'x-internal-token': TOKEN }, { 'x-internal-token': '' }]) {
      const r = await call(headers);
      assert.equal(r.status, 503);
      assert.match(r.body.error, /not configured/);
    }
  });
});

test('a whitespace-only token counts as not configured', async () => {
  await withApp({ token: () => '   ', development: () => false }, async (call) => assert.equal((await call()).status, 503));
});

test('with no token configured, a development environment stays open so a local stack keeps working', async () => {
  await withApp({ token: () => '', development: () => true }, async (call) => assert.equal((await call()).status, 200));
});

test('a configured token is enforced in development too', async () => {
  await withApp({ token: () => TOKEN, development: () => true }, async (call) => {
    assert.equal((await call()).status, 401);
    assert.equal((await call({ 'x-internal-token': TOKEN })).status, 200);
  });
});

test('checkInternalToken decisions', () => {
  assert.equal(checkInternalToken(TOKEN, TOKEN, false), 'ok');
  assert.equal(checkInternalToken(TOKEN, '', false), 'unauthorized');
  assert.equal(checkInternalToken(TOKEN, 'nope', true), 'unauthorized');
  assert.equal(checkInternalToken('', 'anything', false), 'unconfigured');
  assert.equal(checkInternalToken('', '', true), 'ok');
});

test('isDevelopmentEnv: unset is a local run; set-but-empty or unrecognised is NOT development', () => {
  assert.equal(isDevelopmentEnv({}), true);
  for (const v of ['development', 'dev', 'local', 'test', 'Development', ' DEV ']) assert.equal(isDevelopmentEnv({ ENVIRONMENT: v }), true, v);
  for (const v of ['production', 'prod', 'staging', 'prodution', '', '   ']) assert.equal(isDevelopmentEnv({ ENVIRONMENT: v }), false, JSON.stringify(v));
  assert.equal(isDevelopmentEnv({ AISOC_ENV: 'production', ENVIRONMENT: 'development' }), false, 'AISOC_ENV takes precedence');
  assert.equal(isDevelopmentEnv({ AISOC_ENV: '', ENVIRONMENT: 'development' }), false, 'an empty AISOC_ENV must not fall through to development');
});

test('presentedInternalToken reads both header names and prefers neither blank', () => {
  assert.equal(presentedInternalToken({ 'x-internal-token': 'a' }), 'a');
  assert.equal(presentedInternalToken({ 'x-aisoc-internal-token': 'b' }), 'b');
  assert.equal(presentedInternalToken({ 'x-aisoc-internal-token': '', 'x-internal-token': 'c' }), 'c');
  assert.equal(presentedInternalToken({}), '');
});

// ----------------------------------------------------------------------- the routes ----
const INDEX = fs.readFileSync(path.join(__dirname, '..', 'src', 'index.ts'), 'utf8');
const PUBLIC_ROUTES = new Map<string, string>([
  ['/sse', 'authenticated by its own signed ticket (?token=)'],
  ['/health', 'health check'],
  ['/healthz', 'health check'],
  ['/v1/push/public-key', 'the VAPID public key is public by definition'],
]);

function declaredRoutes(): { method: string; route: string; line: string }[] {
  return [...INDEX.matchAll(/^app\.(get|post|put|patch|delete|all)\(\s*'([^']+)'[^\n]*$/gm)].map((m) => ({ method: m[1], route: m[2], line: m[0] }));
}

test('the sweep finds the routes', () => {
  const routes = declaredRoutes().map((r) => r.route);
  for (const expected of ['/internal/push', '/internal/agent-event', '/v1/push/subscribe', '/v1/push/unsubscribe', '/v1/push/test', '/sse']) {
    assert.ok(routes.includes(expected), `${expected} not found: the route scan is stale`);
  }
});

test('every route in index.ts needs the internal token unless it is on the explicit public list', () => {
  for (const { method, route, line } of declaredRoutes()) {
    if (PUBLIC_ROUTES.has(route)) continue;
    assert.match(line, /requireInternalToken/, `${method.toUpperCase()} ${route} is reachable without the internal token`);
  }
});

test('every public entry is a real route', () => {
  const routes = new Set(declaredRoutes().map((r) => r.route));
  for (const route of PUBLIC_ROUTES.keys()) assert.ok(routes.has(route), `${route} is on the public list but is not a route`);
});

test('the old fail-open check is gone', () => {
  assert.doesNotMatch(INDEX, /requireInternal\(/);
  assert.doesNotMatch(INDEX, /if \(!INTERNAL_TOKEN\) return true/);
});
