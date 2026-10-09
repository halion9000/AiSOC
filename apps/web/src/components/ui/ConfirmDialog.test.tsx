import { fireEvent, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';

import { ConfirmDialog } from './ConfirmDialog';

// The one prompt every destructive action in the app goes through. Safe by default: focus on Cancel, Escape and an outside click cancel, nothing is confirmed except by clicking confirm.
function setup(over: Partial<React.ComponentProps<typeof ConfirmDialog>> = {}) {
  const onConfirm = vi.fn();
  const onCancel = vi.fn();
  const utils = render(<ConfirmDialog open title="Delete playbook?" message='Permanently delete "Phishing triage"? This cannot be undone.' onConfirm={onConfirm} onCancel={onCancel} {...over} />);
  return { onConfirm, onCancel, ...utils };
}

describe('the dialog', () => {
  it('renders nothing when closed', () => {
    const { container } = setup({ open: false });
    expect(container).toBeEmptyDOMElement();
  });

  it('names what will be deleted and is an accessible, modal alert dialog', () => {
    setup();
    const dialog = screen.getByRole('alertdialog', { name: 'Delete playbook?' });
    expect(dialog).toHaveAttribute('aria-modal', 'true');
    expect(dialog).toHaveAccessibleDescription(/Permanently delete "Phishing triage"\? This cannot be undone\./);
  });

  it('puts focus on CANCEL, the safe choice, not on the destructive button', () => {
    setup();
    expect(screen.getByRole('button', { name: 'Cancel' })).toHaveFocus();
  });

  it('confirms ONLY by clicking the confirm button, once', async () => {
    const { onConfirm, onCancel } = setup();
    await userEvent.setup().click(screen.getByRole('button', { name: 'Delete' }));
    expect(onConfirm).toHaveBeenCalledTimes(1);
    expect(onCancel).not.toHaveBeenCalled();
  });

  it('does not confirm when Enter is pressed with focus on Cancel (the default focus)', async () => {
    const { onConfirm, onCancel } = setup();
    await userEvent.setup().keyboard('{Enter}');
    expect(onConfirm).not.toHaveBeenCalled();
    expect(onCancel).toHaveBeenCalledTimes(1); // Enter on the focused Cancel button cancels
  });

  it('cancels on Escape', async () => {
    const { onConfirm, onCancel } = setup();
    await userEvent.setup().keyboard('{Escape}');
    expect(onCancel).toHaveBeenCalledTimes(1);
    expect(onConfirm).not.toHaveBeenCalled();
  });

  it('cancels on a click outside the dialog but not on a click inside it', () => {
    const { onCancel, onConfirm } = setup();
    fireEvent.mouseDown(screen.getByRole('alertdialog'));
    expect(onCancel).not.toHaveBeenCalled();
    fireEvent.mouseDown(screen.getByRole('alertdialog').parentElement!);
    expect(onCancel).toHaveBeenCalledTimes(1);
    expect(onConfirm).not.toHaveBeenCalled();
  });

  it('keeps Tab inside the dialog, in both directions', async () => {
    setup();
    const user = userEvent.setup();
    const cancel = screen.getByRole('button', { name: 'Cancel' });
    const confirm = screen.getByRole('button', { name: 'Delete' });
    await user.tab();
    expect(confirm).toHaveFocus();
    await user.tab();
    expect(cancel).toHaveFocus();
    await user.tab({ shift: true });
    expect(confirm).toHaveFocus();
  });

  it('while busy: shows progress, disables both buttons, and ignores Escape, outside clicks and further confirms', async () => {
    const { onConfirm, onCancel } = setup({ busy: true });
    expect(screen.getByRole('button', { name: 'Working...' })).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Cancel' })).toBeDisabled();
    // Dispatch on the dialog itself: with both buttons disabled nothing inside it can hold focus, so userEvent.keyboard would send the key to <body> and never reach the handler (this assertion was vacuous before).
    fireEvent.keyDown(screen.getByRole('alertdialog'), { key: 'Escape' });
    fireEvent.mouseDown(screen.getByRole('alertdialog').parentElement!);
    fireEvent.click(screen.getByRole('button', { name: 'Working...' }));
    expect(onCancel).not.toHaveBeenCalled();
    expect(onConfirm).not.toHaveBeenCalled();
  });

  it('uses the given labels and a non-destructive style on request', () => {
    setup({ confirmLabel: 'Revoke key', cancelLabel: 'Keep it', destructive: false });
    expect(screen.getByRole('button', { name: 'Revoke key' }).className).toContain('emerald');
    expect(screen.getByRole('button', { name: 'Keep it' })).toBeInTheDocument();
  });

  it('uses the destructive style by default', () => {
    setup();
    expect(screen.getByRole('button', { name: 'Delete' }).className).toContain('red');
  });
});
