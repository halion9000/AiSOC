import { describe, expect, it } from 'vitest';
import { ALL_FORMATS, FORMAT_LABELS, decodePermalink, encodePermalink, translateRule, type DetectionFormat } from './translate';

describe('translateRule', () => {
  it('gives the same rule back for the format it is already in', () => {
    const out = translateRule('EventID: 4625', 'sigma', ['sigma', 'spl']);
    expect(out.results[0]).toMatchObject({ format: 'sigma', rule: 'EventID: 4625', notes: 'Same as source.' });
  });

  it('renames the common fields for each target and wraps the rule the way that product expects', () => {
    const rule = 'EventID=4688 and Image endswith "powershell.exe" and DestinationIp="10.0.0.1"';
    const by = Object.fromEntries(translateRule(rule, 'sigma', ['spl', 'kql', 'esql', 'yara_l2', 'udm']).results.map((r) => [r.format, r.rule]));
    expect(by.spl).toBe('index=* sourcetype=WinEventLog\n| search EventCode=4688 and process_name endswith "powershell.exe" and dest_ip="10.0.0.1"');
    expect(by.kql).toBe('SecurityEvent\n| where EventID=4688 and NewProcessName endswith "powershell.exe" and RemoteIP="10.0.0.1"');
    expect(by.esql).toBe('FROM logs-*\n| WHERE event.code=4688 and process.executable endswith "powershell.exe" and destination.ip="10.0.0.1"');
    expect(by.yara_l2).toContain('principal.process.file.full_path endswith');
    expect(by.yara_l2).toMatch(/^rule translated_rule \{[\s\S]*condition:[\s\S]*\}$/);
    expect(by.udm.startsWith('// Chronicle UDM Search\n')).toBe(true);
  });

  it('defaults to four targets, with the source format passed through unchanged', () => {
    const out = translateRule('x', 'spl');
    expect(out.results.map((r) => r.format)).toEqual(['sigma', 'spl', 'kql', 'esql']);
    expect(out.results[1].rule).toBe('x');
  });

  it('always carries the honest warning that this is a field-name template, not a full translation', () => {
    const out = translateRule('x', 'sigma');
    expect(out.warnings[0]).toMatch(/Review field names/);
    expect(out.sourceFormat).toBe('sigma');
  });

  it('every format has a label and a wrapper (nothing is left unlabeled or throws)', () => {
    expect(ALL_FORMATS).toHaveLength(6);
    for (const f of ALL_FORMATS) {
      expect(FORMAT_LABELS[f].length).toBeGreaterThan(3);
      expect(() => translateRule('EventID=1', 'sigma', [f])).not.toThrow();
    }
  });

  it('renames only whole field names: ParentImage, ImageLoaded and EventIDs are left alone', () => {
    const out = translateRule('ParentImage endswith "cmd.exe" and ImageLoaded contains "x" and EventIDs=1', 'sigma', ['spl', 'esql']);
    for (const r of out.results) {
      expect(r.rule).toContain('ParentImage');
      expect(r.rule).toContain('ImageLoaded');
      expect(r.rule).toContain('EventIDs');
    }
  });

  it('still renames a field at the start or end of the rule, or next to punctuation', () => {
    const out = translateRule('Image|endswith: x\nCommandLine', 'sigma', ['esql']);
    expect(out.results[0].rule).toContain('process.executable|endswith: x');
    expect(out.results[0].rule.endsWith('process.command_line')).toBe(true);
  });
});

describe('permalinks', () => {
  const cases: Array<[DetectionFormat, string]> = [
    ['sigma', 'title: x\ndetection:\n  selection:\n    Image: cmd.exe'],
    ['kql', 'SecurityEvent | where Account == "café ☕" and Note == "日本語"'],
    ['esql', 'x'.repeat(500)],
    ['spl', ''],
  ];
  it('round-trips any rule, including accents, symbols and an empty one', () => {
    for (const [f, r] of cases) expect(decodePermalink(encodePermalink(f, r))).toEqual({ sourceFormat: f, rule: r });
  });
  it('is URL-safe: no +, / or = in the code', () => {
    for (const [f, r] of cases) expect(encodePermalink(f, r)).toMatch(/^[A-Za-z0-9_-]*$/);
    expect(encodePermalink('sigma', '???>>>~~~')).toMatch(/^[A-Za-z0-9_-]+$/);
  });
  it('refuses anything that is not one of ours: junk, a wrong format, a wrong shape', () => {
    const b64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString('base64url');
    for (const bad of ['', '!!!', 'not-base64-json', b64({ f: 'nope', r: 'x' }), b64({ f: 'sigma', r: 5 }), b64('string'), b64(null)]) {
      expect(decodePermalink(bad), bad).toBeNull();
    }
  });
});
