import { describe, expect, it } from 'vitest';
import { parseAlertText } from './alert-text';

const SAMPLE = [
  'Client: Live Oak IT Partners',
  'Host: DESKTOP-1',
  'Sensor: Cloud',
  '',
  'On 03 October 2026 account mark@example.com was observed authenticating over a VPN.',
  '',
  '**Security Context**',
  '',
  'Threat actors frequently use commodity VPN providers.',
  '',
  '<br/>',
  '',
  '**Affected Account**',
  '',
  'The table below provides the details.',
  '| | |',
  '|--|--|',
  '| Account | **mark@example.com** |',
  '| Country | Canada |',
  '<br/> ----',
  '**ARO Resolution**',
  '- Dismiss this ARO if expected.',
  '- Resolve this ARO after mitigation.',
].join('\n');

describe('parseAlertText', () => {
  const blocks = parseAlertText(SAMPLE);

  it('turns leading Label: value lines into one fact list', () => {
    expect(blocks[0]).toMatchObject({ type: 'facts' });
    expect((blocks[0] as { rows: unknown[] }).rows).toHaveLength(3);
  });

  it('turns **Heading** lines into headings and drops the <br/> tags', () => {
    expect(blocks.filter((b) => b.type === 'heading').map((b) => (b as { text: string }).text)).toEqual(['Security Context', 'Affected Account', 'ARO Resolution']);
    expect(JSON.stringify(blocks)).not.toContain('<br');
  });

  it('reads the table as label/value rows, skipping the empty header and the separator', () => {
    const table = blocks.filter((b) => b.type === 'facts')[1] as { rows: Array<[string, Array<{ text: string }>]> };
    expect(table.rows.map((r) => r[0])).toEqual(['Account', 'Country']);
    expect(table.rows[0][1][0].text).toBe('mark@example.com');
  });

  it('keeps a bullet list as a list', () => {
    const list = blocks.find((b) => b.type === 'list') as { items: unknown[] };
    expect(list.items).toHaveLength(2);
  });

  it('leaves plain text as one paragraph and an empty string as nothing', () => {
    expect(parseAlertText('Just a sentence.\nStill the same one.')).toHaveLength(1);
    expect(parseAlertText('')).toEqual([]);
  });

  it('does not treat a single Label: value line as a fact list', () => {
    expect(parseAlertText('Status: reported. Binary: /usr/bin/x')[0]).toMatchObject({ type: 'p' });
  });
});
