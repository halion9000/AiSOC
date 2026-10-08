import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

const copilotApi = vi.hoisted(() => ({ listConversations: vi.fn(), getConversation: vi.fn(), chat: vi.fn() }));
vi.mock('@/lib/api', async (importOriginal) => ({ ...(await importOriginal<typeof import('@/lib/api')>()), copilotApi }));
vi.mock('next/navigation', () => ({ usePathname: () => '/alerts' }));
vi.mock('@/lib/auth-session', async (importOriginal) => ({ ...(await importOriginal<typeof import('@/lib/auth-session')>()), authFetch: vi.fn(async () => new Response('{}', { status: 200 })) }));

import { ApiError } from '@/lib/api';
import { CopilotDock } from './CopilotDock';

// When the copilot was unavailable the dock's header said "Offline (demo)", although nothing demo-ish happens (it shows no sample data), and its message said only that the backend was
// "unreachable" even when the backend had answered with the specific reason.
const noKey = () => new ApiError('API 503', 503, JSON.stringify({ detail: 'The copilot cannot answer right now: no language-model API key is configured for the copilot.' }));

beforeEach(() => {
  Object.values(copilotApi).forEach((m) => m.mockReset());
});

async function openAndAsk(text: string) {
  const user = userEvent.setup();
  await user.click(screen.getByRole('button', { name: 'Open AI Copilot' }));
  await user.type(screen.getByPlaceholderText(/Ask Copilot/), text);
  await user.click(screen.getByRole('button', { name: 'Send' }));
}

describe('the dock when the copilot cannot answer', () => {
  it("shows the backend's real reason, and says Offline (not 'Offline (demo)')", async () => {
    copilotApi.chat.mockRejectedValue(noKey());
    const { container } = render(<CopilotDock />);
    await openAndAsk('Is this IP malicious?');
    expect(await screen.findByText(/The copilot could not answer: The copilot cannot answer right now: no language-model API key is configured for the copilot\./)).toBeInTheDocument();
    expect(await screen.findByText('Offline')).toBeInTheDocument();
    expect(container.textContent).not.toMatch(/demo/i);
    expect(container.textContent).not.toContain('..');
  });

  it('says the API could not be reached for a network failure', async () => {
    copilotApi.chat.mockRejectedValue(new ApiError('Network error', 0, ''));
    render(<CopilotDock />);
    await openAndAsk('Anything?');
    expect(await screen.findByText(/The copilot could not answer: the AiSOC API could not be reached\./)).toBeInTheDocument();
  });
});

describe('the dock when it answers', () => {
  it('shows the answer and no failure notice', async () => {
    copilotApi.chat.mockResolvedValue({ conversationId: 'c1', reply: { id: 'a1', role: 'assistant', content: 'Block the sender.', createdAt: '2026-10-08T00:00:00Z' } });
    render(<CopilotDock />);
    await openAndAsk('What now?');
    expect(await screen.findByText('Block the sender.')).toBeInTheDocument();
    expect(screen.queryByText(/could not answer/)).not.toBeInTheDocument();
    expect(await screen.findByText('Connected')).toBeInTheDocument();
  });
});
