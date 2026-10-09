import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

const copilotApi = vi.hoisted(() => ({ listConversations: vi.fn(), getConversation: vi.fn(), chat: vi.fn(), confirmAction: vi.fn() }));
vi.mock('@/lib/api', async (importOriginal) => ({ ...(await importOriginal<typeof import('@/lib/api')>()), copilotApi }));

import { ApiError } from '@/lib/api';
import { CopilotView } from './CopilotView';

// On any failure this page showed a canned "The AI backend is currently unreachable" even when the backend WAS reached and said why it could not answer (for example, that no language-model
// API key is configured), and offered "Retry" / "Open AISOC status" chips that, when clicked, sent that text to the model as a prompt.
const reply = { id: 'a1', role: 'assistant' as const, content: 'The sender domain was registered yesterday.', createdAt: '2026-10-08T00:00:00Z' };
const noKey = () => new ApiError('API 503', 503, JSON.stringify({ detail: 'The copilot cannot answer right now: no language-model API key is configured for the copilot.' }));

beforeEach(() => {
  Object.values(copilotApi).forEach((m) => m.mockReset());
  copilotApi.listConversations.mockResolvedValue({ conversations: [] });
});

async function ask(text: string) {
  const user = userEvent.setup();
  await user.type(screen.getByPlaceholderText(/Ask anything/), text);
  await user.click(screen.getByRole('button', { name: /^send$/i }));
}

describe('when the copilot cannot answer', () => {
  it("shows the backend's real reason, the user's own message, and that it is offline", async () => {
    copilotApi.chat.mockRejectedValue(noKey());
    render(<CopilotView />);
    await ask('Is this IP malicious?');
    expect(await screen.findByText(/The copilot could not answer: The copilot cannot answer right now: no language-model API key is configured for the copilot\./)).toBeInTheDocument();
    expect(screen.getByText(/Your message was: "Is this IP malicious\?"/)).toBeInTheDocument();
    expect(screen.getByText('Offline')).toBeInTheDocument();
    expect(screen.queryByText(/\.\./)).not.toBeInTheDocument(); // no doubled full stop
  });

  it('does not offer suggestion chips that would be sent to the model as prompts', async () => {
    copilotApi.chat.mockRejectedValue(noKey());
    render(<CopilotView />);
    await ask('Anything?');
    await screen.findByText(/The copilot could not answer/);
    expect(screen.queryByText('Open AISOC status')).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Retry' })).not.toBeInTheDocument();
  });

  it('says the API could not be reached for a network failure', async () => {
    copilotApi.chat.mockRejectedValue(new ApiError('Network error talking to /api/v1/copilot/chat: Failed to fetch', 0, ''));
    render(<CopilotView />);
    await ask('Anything?');
    expect(await screen.findByText(/The copilot could not answer: the AiSOC API could not be reached\./)).toBeInTheDocument();
  });
});

describe('when it answers', () => {
  it('shows the answer and that it is connected', async () => {
    copilotApi.chat.mockResolvedValue({ conversationId: 'c1', reply });
    render(<CopilotView />);
    await ask('Why is this phishing?');
    expect(await screen.findByText('The sender domain was registered yesterday.')).toBeInTheDocument();
    expect(screen.getByText('Connected')).toBeInTheDocument();
    expect(screen.queryByText(/could not answer/)).not.toBeInTheDocument();
  });
});

describe('when the copilot asks to delete something', () => {
  const asksToDelete = {
    conversationId: 'c1',
    reply: { id: 'a9', role: 'assistant' as const, content: 'I have asked you to confirm the deletion.', createdAt: '2026-10-08T00:00:00Z' },
    pendingActions: [{ action: 'delete_alert', summary: 'Permanently delete alert "Beaconing host"? This cannot be undone.', token: 'tok-view', expiresAt: Math.floor(Date.now() / 1000) + 300 }],
  };

  it('shows a confirmation prompt under the reply and has deleted nothing yet', async () => {
    copilotApi.chat.mockResolvedValue(asksToDelete);
    render(<CopilotView />);
    await ask('delete that alert');
    expect(await screen.findByRole('group', { name: 'Confirmation required' })).toBeInTheDocument();
    expect(screen.getByText(/Permanently delete alert "Beaconing host"/)).toBeInTheDocument();
    expect(copilotApi.confirmAction).not.toHaveBeenCalled();
  });

  it("deletes only when the analyst clicks, with that prompt's own token", async () => {
    copilotApi.chat.mockResolvedValue(asksToDelete);
    copilotApi.confirmAction.mockResolvedValue({ status: 'done', action: 'delete_alert', result: { deleted: true } });
    render(<CopilotView />);
    await ask('delete that alert');
    await userEvent.setup().click(await screen.findByRole('button', { name: 'Delete' }));
    expect(await screen.findByText('Deleted.')).toBeInTheDocument();
    expect(copilotApi.confirmAction).toHaveBeenCalledTimes(1);
    expect(copilotApi.confirmAction).toHaveBeenCalledWith('tok-view');
  });

  it('shows no prompt for an ordinary reply', async () => {
    copilotApi.chat.mockResolvedValue({ conversationId: 'c1', reply });
    render(<CopilotView />);
    await ask('what is this domain?');
    expect(await screen.findByText(/The sender domain was registered yesterday/)).toBeInTheDocument();
    expect(screen.queryByRole('group', { name: 'Confirmation required' })).not.toBeInTheDocument();
  });
});
