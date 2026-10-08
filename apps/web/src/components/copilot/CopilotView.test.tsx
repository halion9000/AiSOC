import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

const copilotApi = vi.hoisted(() => ({ listConversations: vi.fn(), getConversation: vi.fn(), chat: vi.fn() }));
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
