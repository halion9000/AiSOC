import { describe, expect, it, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import matter from 'gray-matter';

import { SimpleRuleBuilder, buildSigma } from './SimpleRuleBuilder';

/** Reads the generated rule the way a real YAML reader would. */
const parse = (sigma: string): Record<string, any> => matter(`---\n${sigma}\n---\n`).data;

const base = { title: 'Encoded PowerShell', product: 'windows', category: 'process_creation', level: 'high' };

describe('buildSigma', () => {
  it('writes a Sigma rule a YAML reader understands, with the logsource, one selection and the level', () => {
    const doc = parse(buildSigma({ ...base, conditions: [{ field: 'CommandLine', operator: 'contains', value: '-enc' }, { field: 'Image', operator: 'endswith', value: 'powershell.exe' }] }));
    expect(doc.title).toBe('Encoded PowerShell');
    expect(doc.status).toBe('experimental');
    expect(doc.logsource).toEqual({ product: 'windows', category: 'process_creation' });
    expect(doc.detection.selection).toEqual({ 'CommandLine|contains': '-enc', 'Image|endswith': 'powershell.exe' });
    expect(doc.detection.condition).toBe('selection');
    expect(doc.level).toBe('high');
  });

  it('"equals" is a plain field, the other operators are modifiers', () => {
    const doc = parse(buildSigma({ ...base, conditions: [{ field: 'EventID', operator: 'equals', value: '4688' }, { field: 'User', operator: 'startswith', value: 'svc-' }] }));
    expect(Object.keys(doc.detection.selection)).toEqual(['EventID', 'User|startswith']);
  });

  it('keeps values exactly as typed, including quotes, colons, hashes, backslashes and leading symbols', () => {
    const values = ["it's", 'a: b', 'x # not a comment', 'C:\\Windows\\System32\\cmd.exe', '- starts with dash', '*wild*', '{curly}', 'yes', '123', 'null'];
    const doc = parse(buildSigma({ ...base, conditions: values.map((value, i) => ({ field: `F${i}`, operator: 'equals' as const, value })) }));
    values.forEach((v, i) => expect(doc.detection.selection[`F${i}`], v).toBe(v));
  });

  it('a title with a colon, hash or quote is still valid and still the title the person typed', () => {
    for (const title of ['Suspicious: PowerShell', 'Rule #1', "Admin's login", '- leading dash', 'plain']) {
      const doc = parse(buildSigma({ ...base, title, conditions: [{ field: 'A', operator: 'equals', value: 'b' }] }));
      expect(doc.title, title).toBe(title);
    }
  });

  it('a field name with a colon or a symbol is quoted so it is still a valid key', () => {
    const doc = parse(buildSigma({ ...base, conditions: [{ field: 'Event: Data', operator: 'contains', value: 'x' }, { field: '@timestamp', operator: 'equals', value: 'y' }] }));
    expect(doc.detection.selection).toEqual({ 'Event: Data|contains': 'x', '@timestamp': 'y' });
  });

  it('a missing title becomes "Untitled detection"', () => {
    expect(parse(buildSigma({ ...base, title: '', conditions: [{ field: 'A', operator: 'equals', value: 'b' }] })).title).toBe('Untitled detection');
  });

  it('leaves out an empty product or category rather than writing an empty line', () => {
    const doc = parse(buildSigma({ ...base, product: '', category: '', conditions: [{ field: 'A', operator: 'equals', value: 'b' }] }));
    expect(doc.logsource).toBeNull();
    const only = parse(buildSigma({ ...base, product: '', conditions: [{ field: 'A', operator: 'equals', value: 'b' }] }));
    expect(only.logsource).toEqual({ category: 'process_creation' });
  });

  it('skips a condition that has no field or no value, and with none left it still gives a valid rule', () => {
    const doc = parse(buildSigma({ ...base, conditions: [{ field: '', operator: 'equals', value: 'x' }, { field: 'A', operator: 'equals', value: '  ' }, { field: 'B', operator: 'equals', value: 'ok' }] }));
    expect(doc.detection.selection).toEqual({ B: 'ok' });
    const none = parse(buildSigma({ ...base, conditions: [] }));
    expect(none.detection.selection).toEqual({ EventID: '' });
    expect(none.detection.condition).toBe('selection');
  });

  it('always ends with a newline', () => {
    expect(buildSigma({ ...base, conditions: [] }).endsWith('\n')).toBe(true);
  });
});

describe('SimpleRuleBuilder', () => {
  it('Generate Sigma hands the finished rule to the editor', async () => {
    const onGenerate = vi.fn();
    render(<SimpleRuleBuilder onGenerate={onGenerate} />);
    await userEvent.type(screen.getByPlaceholderText('Rule title'), 'Suspicious: encoded command');
    await userEvent.type(screen.getByPlaceholderText('value'), '-enc');
    await userEvent.click(screen.getByRole('button', { name: 'Generate Sigma' }));
    expect(onGenerate).toHaveBeenCalledTimes(1);
    const doc = parse(onGenerate.mock.calls[0][0]);
    expect(doc.title).toBe('Suspicious: encoded command');
    expect(doc.detection.selection).toEqual({ 'CommandLine|contains': '-enc' });
    expect(doc.logsource).toEqual({ product: 'windows', category: 'process_creation' });
    expect(doc.level).toBe('medium');
  });

  it('conditions can be added and removed, but the last one cannot be removed', async () => {
    render(<SimpleRuleBuilder onGenerate={() => {}} />);
    expect(screen.queryByRole('button', { name: 'Remove condition' })).toBeNull();
    await userEvent.click(screen.getByRole('button', { name: '+ Add condition' }));
    expect(screen.getAllByPlaceholderText('field')).toHaveLength(2);
    await userEvent.click(screen.getAllByRole('button', { name: 'Remove condition' })[0]);
    expect(screen.getAllByPlaceholderText('field')).toHaveLength(1);
    expect(screen.queryByRole('button', { name: 'Remove condition' })).toBeNull();
  });

  it('removing one condition removes that one, not another', async () => {
    const onGenerate = vi.fn();
    render(<SimpleRuleBuilder onGenerate={onGenerate} />);
    await userEvent.type(screen.getByPlaceholderText('value'), 'first');
    await userEvent.click(screen.getByRole('button', { name: '+ Add condition' }));
    await userEvent.type(screen.getAllByPlaceholderText('field')[1], 'Second');
    await userEvent.type(screen.getAllByPlaceholderText('value')[1], 'two');
    await userEvent.click(screen.getAllByRole('button', { name: 'Remove condition' })[0]);
    await userEvent.click(screen.getByRole('button', { name: 'Generate Sigma' }));
    expect(parse(onGenerate.mock.calls[0][0]).detection.selection).toEqual({ 'Second|contains': 'two' });
  });

  it('the level and the operator can be changed', async () => {
    const onGenerate = vi.fn();
    render(<SimpleRuleBuilder onGenerate={onGenerate} />);
    const [operator, level] = screen.getAllByRole('combobox');
    await userEvent.selectOptions(operator, 'startswith');
    await userEvent.selectOptions(level, 'critical');
    await userEvent.type(screen.getByPlaceholderText('value'), 'x');
    await userEvent.click(screen.getByRole('button', { name: 'Generate Sigma' }));
    const doc = parse(onGenerate.mock.calls[0][0]);
    expect(doc.level).toBe('critical');
    expect(Object.keys(doc.detection.selection)).toEqual(['CommandLine|startswith']);
  });
});
