import { beforeEach, describe, expect, it, vi } from 'vitest';
import { act, fireEvent, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

const nav = vi.hoisted(() => ({ push: vi.fn(), pathname: '/alerts' }));
const toast = vi.hoisted(() => ({ success: vi.fn(), error: vi.fn() }));
vi.mock('next/navigation', () => ({ useRouter: () => ({ push: nav.push }), usePathname: () => nav.pathname }));
vi.mock('react-hot-toast', () => ({ __esModule: true, default: toast }));
vi.mock('framer-motion', async () => {
  const React = await import('react');
  const strip = ({ children, initial, animate, exit, transition, ...rest }: Record<string, unknown>) => React.createElement('div', rest as object, children as React.ReactNode);
  return { motion: { div: strip }, AnimatePresence: ({ children }: { children: React.ReactNode }) => React.createElement(React.Fragment, null, children) };
});

import { CommandPalette } from './CommandPalette';

const KEY = 'aisoc.palette.recent';

beforeEach(() => {
  nav.push.mockReset();
  nav.pathname = '/alerts';
  toast.success.mockReset();
  toast.error.mockReset();
  localStorage.clear();
  // cmdk measures and scrolls; jsdom has neither.
  (globalThis as Record<string, unknown>).ResizeObserver ??= class { observe() {} unobserve() {} disconnect() {} };
  Element.prototype.scrollIntoView ??= () => {};
});

const openIt = () => {
  render(<CommandPalette />);
  fireEvent.keyDown(window, { key: 'k', ctrlKey: true });
};

describe('CommandPalette', () => {
  it('is closed until Ctrl+K or Cmd+K, which also closes it again', () => {
    render(<CommandPalette />);
    expect(screen.queryByRole('dialog')).toBeNull();
    fireEvent.keyDown(window, { key: 'k', ctrlKey: true });
    expect(screen.getByRole('dialog', { name: 'Command palette' })).toBeInTheDocument();
    fireEvent.keyDown(window, { key: 'K', metaKey: true });
    expect(screen.queryByRole('dialog')).toBeNull();
  });

  it('ignores K on its own and other shortcuts', () => {
    render(<CommandPalette />);
    fireEvent.keyDown(window, { key: 'k' });
    fireEvent.keyDown(window, { key: 'j', ctrlKey: true });
    expect(screen.queryByRole('dialog')).toBeNull();
  });

  it('does not take Ctrl+K away from the rule editor', () => {
    render(<CommandPalette />);
    const editor = document.createElement('div');
    editor.className = 'monaco-editor';
    const inner = document.createElement('textarea');
    editor.appendChild(inner);
    document.body.appendChild(editor);
    fireEvent.keyDown(inner, { key: 'k', ctrlKey: true });
    expect(screen.queryByRole('dialog')).toBeNull();
    editor.remove();
  });

  it('lists the pages and the quick actions', () => {
    openIt();
    for (const label of ['Dashboard', 'Alerts', 'Cases', 'Hunt', 'Detection Rules', 'Threat Intel', 'Connectors', 'Settings', 'User guide']) expect(screen.getByText(label)).toBeInTheDocument();
    for (const label of ['Ask A.C.O.R.N Copilot', 'Open AI Copilot page', 'Refresh data', 'Copy current URL']) expect(screen.getByText(label)).toBeInTheDocument();
    expect(screen.getByText('Navigation')).toBeInTheDocument();
    expect(screen.getByText('Quick actions')).toBeInTheDocument();
  });

  it('choosing a page goes there and closes the palette', async () => {
    openIt();
    await userEvent.click(screen.getByText('Cases'));
    expect(nav.push).toHaveBeenCalledWith('/cases');
    expect(screen.queryByRole('dialog')).toBeNull();
  });

  it('typing narrows the list, matching on the extra keywords too', async () => {
    openIt();
    await userEvent.type(screen.getByPlaceholderText(/Type a command/), 'sigma');
    expect(screen.getByText('Detection Rules')).toBeInTheDocument();
    expect(screen.queryByText('Cases')).toBeNull();
  });

  it('says so when nothing matches', async () => {
    openIt();
    await userEvent.type(screen.getByPlaceholderText(/Type a command/), 'zzzzqqq');
    expect(screen.getByText(/No matches/)).toBeInTheDocument();
  });

  it('the Copilot action tells the dock to open and closes the palette', async () => {
    const heard = vi.fn();
    window.addEventListener('aisoc:open-copilot', heard);
    openIt();
    await userEvent.click(screen.getByText('Ask A.C.O.R.N Copilot'));
    expect(heard).toHaveBeenCalledTimes(1);
    expect(screen.queryByRole('dialog')).toBeNull();
    window.removeEventListener('aisoc:open-copilot', heard);
  });

  it('Copy current URL copies the address and says so, or says it could not', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, 'clipboard', { value: { writeText }, configurable: true });
    openIt();
    await userEvent.click(screen.getByText('Copy current URL'));
    expect(writeText).toHaveBeenCalledWith(window.location.href);
    expect(toast.success).toHaveBeenCalledWith('URL copied to clipboard');
    writeText.mockRejectedValueOnce(new Error('denied'));
    fireEvent.keyDown(window, { key: 'k', ctrlKey: true });
    await userEvent.click(screen.getByText('Copy current URL'));
    expect(toast.error).toHaveBeenCalledWith('Could not copy URL');
  });

  it('the backdrop closes it', async () => {
    openIt();
    await userEvent.click(screen.getByRole('button', { name: 'Close command palette' }));
    expect(screen.queryByRole('dialog')).toBeNull();
  });

  it('remembers pages visited (newest first, no repeats, at most five) but not the home or login pages', () => {
    const { rerender } = render(<CommandPalette />);
    for (const p of ['/', '/login', '/cases', '/alerts', '/cases', '/hunt', '/explore', '/graph', '/copilot']) {
      nav.pathname = p;
      rerender(<CommandPalette />);
    }
    expect(JSON.parse(localStorage.getItem(KEY) as string)).toEqual(['/copilot', '/graph', '/explore', '/hunt', '/cases']);
  });

  it('shows recent pages, leaving out the one you are on, with the page name where it is known', () => {
    localStorage.setItem(KEY, JSON.stringify(['/alerts', '/cases/1234', '/some/other/place']));
    nav.pathname = '/alerts';
    openIt();
    expect(screen.getByText('Recent pages')).toBeInTheDocument();
    const cases = screen.getByText('/cases/1234').parentElement as HTMLElement;
    expect(cases).toHaveTextContent('Cases');
    expect(screen.getAllByText('/some/other/place')).toHaveLength(2);
    expect(screen.queryAllByText('/alerts')).toHaveLength(1);
  });

  it('a damaged recent list is ignored rather than crashing the palette', () => {
    for (const bad of ['{not json', '"text"', '[1,2,{"a":1}]', 'null']) {
      localStorage.setItem(KEY, bad);
      const { unmount } = render(<CommandPalette />);
      fireEvent.keyDown(window, { key: 'k', ctrlKey: true });
      expect(screen.getByRole('dialog')).toBeInTheDocument();
      expect(screen.queryByText('Recent pages')).toBeNull();
      unmount();
    }
  });

  it('removes its key listener when it goes away', () => {
    const { unmount } = render(<CommandPalette />);
    unmount();
    act(() => {
      fireEvent.keyDown(window, { key: 'k', ctrlKey: true });
    });
    expect(screen.queryByRole('dialog')).toBeNull();
  });
});
