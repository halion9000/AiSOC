import { describe, expect, it, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import matter from 'gray-matter';

import { RuleBuilder } from './RuleBuilder';

/** The snippet is a list item meant to sit under `rules:`; read it as YAML would. */
const parse = (snippet: string): any => matter(`---\nrules:\n${snippet}\n---\n`).data.rules[0];

function setup() {
  const onAppend = vi.fn();
  render(<RuleBuilder onAppend={onAppend} />);
  const type = async (placeholder: string | RegExp, text: string) => userEvent.type(screen.getByPlaceholderText(placeholder), text);
  const append = () => userEvent.click(screen.getByRole('button', { name: 'Append rule to editor' }));
  const snippet = () => onAppend.mock.calls[onAppend.mock.calls.length - 1][0] as string;
  return { onAppend, type, append, snippet };
}

describe('RuleBuilder', () => {
  it('cannot append until there is an id, a value and an action', async () => {
    const { type } = setup();
    const button = screen.getByRole('button', { name: 'Append rule to editor' });
    expect(button).toBeDisabled();
    await type('prod-iam-business-hours', 'r1');
    expect(button).toBeDisabled();
    await type('prod', 'prod');
    expect(button).toBeDisabled();
    await userEvent.selectOptions(screen.getByDisplayValue('— unchanged —'), 'high');
    expect(button).toBeEnabled();
  });

  it('writes a rule that YAML reads back as what was entered', async () => {
    const { type, append, snippet } = setup();
    await type('prod-iam-business-hours', 'prod-iam');
    await type(/Wake tier-2/, 'Wake tier 2');
    await type('prod', 'prod');
    await userEvent.selectOptions(screen.getByDisplayValue('— unchanged —'), 'critical');
    await type('tier2', 'tier2');
    await type('business-hours-prod', 'bh');
    await append();
    expect(parse(snippet())).toEqual({
      id: 'prod-iam',
      description: 'Wake tier 2',
      priority: 100,
      when: { field: 'alert.target.tag', op: 'eq', value: 'prod' },
      then: { set_severity: 'critical', route_to: 'tier2', tag: 'bh' },
    });
  });

  it('"is one of" splits the value on commas into a list, dropping blanks', async () => {
    const { type, append, snippet } = setup();
    await type('prod-iam-business-hours', 'r');
    await userEvent.selectOptions(screen.getByDisplayValue('equals'), 'in');
    await type('prod, staging', 'prod, staging,, dev ');
    await userEvent.click(screen.getByLabelText('Suppress matching alerts'));
    await append();
    expect(parse(snippet()).when).toEqual({ field: 'alert.target.tag', op: 'in', value: ['prod', 'staging', 'dev'] });
    expect(parse(snippet()).then).toEqual({ suppress: true });
  });

  it('numbers and true/false in the condition value stay numbers and booleans, anything else is a string', async () => {
    for (const [typed, expected] of [['42', 42], ['3.5', 3.5], ['true', true], ['false', false], ['prod', 'prod'], ['two words', 'two words'], ['a: b', 'a: b'], ['# x', '# x']] as const) {
      const { unmount } = render(<RuleBuilder onAppend={() => {}} />);
      unmount();
      const { type, append, snippet } = setup();
      await type('prod-iam-business-hours', 'r');
      await type('prod', typed);
      await userEvent.click(screen.getAllByLabelText('Suppress matching alerts')[0]);
      await append();
      expect(parse(snippet()).when.value, typed).toBe(expected);
      document.body.innerHTML = '';
    }
  });

  it('text fields that only look like a number, a boolean or null are quoted so they stay text', async () => {
    const { type, append, snippet } = setup();
    await type('prod-iam-business-hours', 'true');
    await type('tier2', 'null');
    await type('business-hours-prod', '123');
    await type('prod', 'x');
    await append();
    const rule = parse(snippet());
    expect(rule.id).toBe('true');
    expect(rule.then.route_to).toBe('null');
    expect(rule.then.tag).toBe('123');
  });

  it('text with spaces, colons, quotes or hashes is quoted and read back unchanged', async () => {
    const { type, append, snippet } = setup();
    await type('prod-iam-business-hours', 'id: with colon');
    await type(/Wake tier-2/, 'say "hi" # not a comment');
    await type('prod', 'x');
    await type('tier2', "tier 2's queue");
    await append();
    const rule = parse(snippet());
    expect(rule.id).toBe('id: with colon');
    expect(rule.description).toBe('say "hi" # not a comment');
    expect(rule.then.route_to).toBe("tier 2's queue");
  });

  it('after appending it clears the id, description and value but keeps the rest, ready for the next similar rule', async () => {
    const { type, append, onAppend } = setup();
    await type('prod-iam-business-hours', 'r1');
    await type('prod', 'prod');
    await type('tier2', 'tier2');
    await append();
    expect(onAppend).toHaveBeenCalledTimes(1);
    expect(screen.getByPlaceholderText('prod-iam-business-hours')).toHaveValue('');
    expect(screen.getByPlaceholderText('prod')).toHaveValue('');
    expect(screen.getByPlaceholderText('tier2')).toHaveValue('tier2');
    expect(screen.getByRole('button', { name: 'Append rule to editor' })).toBeDisabled();
  });

  it('the priority is written as typed and falls back to 100 when it is emptied', async () => {
    const { type, append, snippet } = setup();
    await type('prod-iam-business-hours', 'r');
    await type('prod', 'x');
    await type('tier2', 't');
    const priority = screen.getByDisplayValue('100');
    await userEvent.clear(priority);
    await userEvent.type(priority, '250');
    await append();
    expect(parse(snippet()).priority).toBe(250);
  });
});
