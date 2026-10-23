import { describe, expect, it } from 'vitest';
import { STEP_SCHEMAS, defaultParamsFor, validateStepParams } from './stepSchemas';
import type { StepType } from './types';

const TYPES: StepType[] = ['enrich', 'investigate', 'notify', 'block_ip', 'isolate_host', 'create_ticket', 'close_case', 'http', 'condition'];

const requiredBase = (t: StepType) => Object.fromEntries(STEP_SCHEMAS[t].fields.filter((f) => f.required).map((f) => [f.key, 'x']));
const firstOfKind = (kind: string) => TYPES.flatMap((t) => STEP_SCHEMAS[t].fields.filter((f) => f.kind === kind).map((f) => ({ t, f })))[0];

describe('the step schemas', () => {
  it('has one for every kind of step, filed under its own name, with a label, an icon and a colour', () => {
    expect(Object.keys(STEP_SCHEMAS).sort()).toEqual([...TYPES].sort());
    for (const t of TYPES) {
      const s = STEP_SCHEMAS[t];
      expect(s.type).toBe(t);
      expect(s.label.length).toBeGreaterThan(2);
      expect(s.description.length).toBeGreaterThan(10);
      expect(s.accent).toMatch(/^#[0-9a-f]{6}$/i);
      expect(s.icon.length).toBeGreaterThan(0);
    }
  });

  it('no step lists the same field twice, every select has options with a value and label, and a select default is one of them', () => {
    for (const t of TYPES) {
      const keys = STEP_SCHEMAS[t].fields.map((f) => f.key);
      expect(new Set(keys).size, t).toBe(keys.length);
      for (const f of STEP_SCHEMAS[t].fields) {
        if (f.kind !== 'select') continue;
        expect(f.options?.length, `${t}.${f.key}`).toBeGreaterThan(0);
        for (const o of f.options ?? []) expect(Boolean(o.value && o.label)).toBe(true);
        if (f.defaultValue !== undefined) expect((f.options ?? []).some((o) => o.value === f.defaultValue), `${t}.${f.key} default`).toBe(true);
      }
    }
  });

  it('the condition step takes no parameters, so it is valid empty', () => {
    expect(STEP_SCHEMAS.condition.fields).toHaveLength(0);
    expect(validateStepParams('condition', {})).toEqual([]);
  });
});

describe('defaultParamsFor', () => {
  it('fills only the fields that have a default, and returns a new object each time', () => {
    for (const t of TYPES) {
      const params = defaultParamsFor(t);
      for (const f of STEP_SCHEMAS[t].fields) {
        if (f.defaultValue !== undefined) expect(params[f.key]).toEqual(f.defaultValue);
        else expect(f.key in params).toBe(false);
      }
    }
    expect(defaultParamsFor('http')).not.toBe(defaultParamsFor('http'));
  });
});

describe('validateStepParams', () => {
  it('names a missing required field, treating empty text, null and undefined as missing', () => {
    const required = STEP_SCHEMAS.enrich.fields.find((f) => f.required);
    expect(required).toBeTruthy();
    const key = (required as { key: string }).key;
    const label = (required as { label: string }).label;
    for (const empty of [undefined, null, '']) expect(validateStepParams('enrich', { [key]: empty })).toEqual([`${label} is required.`]);
    expect(validateStepParams('enrich', { [key]: 'alert.src_ip' })).toEqual([]);
    expect(validateStepParams('enrich', {})).toEqual([`${label} is required.`]);
  });

  it('a number field must hold a number (an empty one is just not filled in)', () => {
    const hit = firstOfKind('number');
    expect(hit).toBeTruthy();
    const { t, f } = hit;
    const base = requiredBase(t);
    expect(validateStepParams(t, { ...base, [f.key]: 'abc' })).toContain(`${f.label} must be a number.`);
    expect(validateStepParams(t, { ...base, [f.key]: 5 })).not.toContain(`${f.label} must be a number.`);
    expect(validateStepParams(t, { ...base, [f.key]: 0 })).not.toContain(`${f.label} must be a number.`);
    expect(validateStepParams(t, { ...base, [f.key]: '' })).not.toContain(`${f.label} must be a number.`);
  });

  it('a boolean field must hold true or false', () => {
    const hit = firstOfKind('boolean');
    if (!hit) return;
    const { t, f } = hit;
    const base = requiredBase(t);
    expect(validateStepParams(t, { ...base, [f.key]: 'yes' })).toContain(`${f.label} must be true/false.`);
    expect(validateStepParams(t, { ...base, [f.key]: false })).not.toContain(`${f.label} must be true/false.`);
  });

  it('a PagerDuty notification needs its service key and a webhook one needs its webhook, and Slack needs neither', () => {
    const base = { message_template: 'hi' };
    const only = (p: Record<string, unknown>) => validateStepParams('notify', p).filter((e) => /requires/.test(e));
    expect(only({ ...base, channel: 'pagerduty' })).toEqual(['PagerDuty channel requires a service-key env var.']);
    expect(only({ ...base, channel: 'pagerduty', service_key_env: 'PD_KEY' })).toEqual([]);
    expect(only({ ...base, channel: 'webhook' })).toEqual(['Webhook channel requires a webhook env var.']);
    expect(only({ ...base, channel: 'webhook', webhook_env: 'HOOK' })).toEqual([]);
    expect(only({ ...base, channel: 'slack' })).toEqual([]);
  });
});
