import { describe, expect, it, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import { StepInspector } from './StepInspector';
import { defaultParamsFor } from './stepSchemas';
import type { PlaybookStep } from './types';

const step = (over: Partial<PlaybookStep> = {}): PlaybookStep => ({
  id: 'step-1',
  name: 'Look up the IP',
  type: 'enrich',
  params: { indicator_field: 'alert.src_ip' },
  on_failure: 'abort',
  retry_max: 1,
  timeout_seconds: 30,
  ...over,
});

function show(over: Partial<PlaybookStep> = {}, props: Record<string, unknown> = {}) {
  const onUpdate = vi.fn();
  const onDelete = vi.fn();
  const view = render(<StepInspector step={step(over)} onUpdate={onUpdate} onDelete={onDelete} {...props} />);
  const last = (): PlaybookStep => onUpdate.mock.calls[onUpdate.mock.calls.length - 1][0];
  return { onUpdate, onDelete, last, ...view };
}

describe('StepInspector', () => {
  it('shows the step: its name, kind, failure handling, retry, timeout and id', () => {
    show();
    expect(screen.getByDisplayValue('Look up the IP')).toBeInTheDocument();
    expect(screen.getByDisplayValue('1')).toBeInTheDocument();
    expect(screen.getByDisplayValue('30')).toBeInTheDocument();
    expect(screen.getByText('id: step-1')).toBeInTheDocument();
    expect(screen.getAllByRole('combobox')[0]).toHaveValue('enrich');
  });

  it('renaming sends the whole step back with the new name', async () => {
    const { last } = show();
    const name = screen.getByDisplayValue('Look up the IP');
    await userEvent.clear(name);
    await userEvent.type(name, 'X');
    expect(last()).toMatchObject({ id: 'step-1', name: 'X', type: 'enrich', params: { indicator_field: 'alert.src_ip' } });
  });

  it('changing the kind of step replaces the parameters with the new kind\'s defaults, so no stale keys survive', async () => {
    const { last } = show();
    await userEvent.selectOptions(screen.getAllByRole('combobox')[0], 'close_case');
    expect(last().type).toBe('close_case');
    expect(last().params).toEqual(defaultParamsFor('close_case'));
    expect(last().params).not.toHaveProperty('indicator_field');
  });

  it('choosing the kind it already is changes nothing', async () => {
    const { onUpdate } = show();
    await userEvent.selectOptions(screen.getAllByRole('combobox')[0], 'enrich');
    expect(onUpdate).not.toHaveBeenCalled();
  });

  it('On failure, retry and timeout are sent as the right kinds of value', async () => {
    const { last } = show();
    const [, onFailure] = screen.getAllByRole('combobox');
    await userEvent.selectOptions(onFailure, 'retry');
    expect(last().on_failure).toBe('retry');
    const retry = screen.getByDisplayValue('1');
    await userEvent.clear(retry);
    await userEvent.type(retry, '3');
    expect(last().retry_max).toBe(3);
    const timeout = screen.getByDisplayValue('30');
    await userEvent.clear(timeout);
    await userEvent.type(timeout, '90');
    expect(last().timeout_seconds).toBe(90);
  });

  it('a condition can be added, its operator changed, and then cleared', async () => {
    const { last } = show();
    await userEvent.type(screen.getByPlaceholderText('field e.g. verdict'), 'v');
    expect(last().condition).toEqual({ field: 'v', operator: 'eq', value: undefined });
    await userEvent.selectOptions(screen.getByDisplayValue('eq'), 'contains');
    expect(last().condition?.operator).toBe('contains');
    await userEvent.type(screen.getByPlaceholderText('value'), 'bad');
    expect(last().condition).toMatchObject({ field: 'v', operator: 'contains', value: 'bad' });
    await userEvent.click(screen.getByRole('button', { name: 'Clear condition' }));
    expect(last().condition).toBeUndefined();
  });

  it('emptying the condition field by hand removes the condition instead of saving one with no field', async () => {
    const { last } = show({ condition: { field: 'verdict', operator: 'eq' } });
    await userEvent.clear(screen.getByPlaceholderText('field e.g. verdict'));
    expect(last().condition).toBeUndefined();
  });

  it('"Clear condition" only appears once there is a condition', () => {
    const { unmount } = show();
    expect(screen.queryByRole('button', { name: 'Clear condition' })).toBeNull();
    unmount();
    show({ condition: { field: 'verdict', operator: 'eq', value: 'bad' } });
    expect(screen.getByRole('button', { name: 'Clear condition' })).toBeInTheDocument();
  });

  it('Delete passes the step\'s id', async () => {
    const { onDelete } = show();
    await userEvent.click(screen.getByRole('button', { name: 'Delete' }));
    expect(onDelete).toHaveBeenCalledWith('step-1');
  });

  it('read-only mode shows everything but offers no Delete and disables every field', () => {
    show({}, { readOnly: true });
    expect(screen.queryByRole('button', { name: 'Delete' })).toBeNull();
    for (const box of [...screen.getAllByRole('textbox'), ...screen.getAllByRole('combobox'), ...screen.getAllByRole('spinbutton')]) expect(box).toBeDisabled();
  });

  it('shows a missing required parameter as a problem to fix', () => {
    show({ params: {} });
    expect(screen.getByText(/Indicator field is required\./)).toBeInTheDocument();
  });

  it('follows a different step handed in from outside', () => {
    const { rerender, onUpdate, onDelete } = show();
    rerender(<StepInspector step={step({ id: 'step-2', name: 'Another' })} onUpdate={onUpdate} onDelete={onDelete} />);
    expect(screen.getByDisplayValue('Another')).toBeInTheDocument();
    expect(screen.getByText('id: step-2')).toBeInTheDocument();
  });
});
