import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

const copilotApi = vi.hoisted(() => ({ listConversations: vi.fn(), getConversation: vi.fn(), chat: vi.fn() }));
vi.mock('@/lib/api', async (importOriginal) => ({ ...(await importOriginal<typeof import('@/lib/api')>()), copilotApi }));

import { CopilotView } from './CopilotView';

// The suggested prompts are SENT TO THE MODEL the moment they are clicked. "Investigate an entity" used to say "Investigate host WIN-FIN-DB01", a host the user's environment almost certainly does not
// have, so clicking it asked the copilot to investigate something that does not exist and invited a made-up answer. The input placeholder suggested the same invented name.
const INVENTED_ASSET = /WIN-FIN-DB01|WORKSTATION-0\d+|DC-0\d|john\.doe|jane\.doe|sasha/i;

beforeEach(() => {
  Object.values(copilotApi).forEach((m) => m.mockReset());
  copilotApi.listConversations.mockResolvedValue({ conversations: [] });
  copilotApi.chat.mockResolvedValue({ conversationId: 'c1', reply: { id: 'a1', role: 'assistant', content: 'ok', createdAt: '2026-10-08T00:00:00Z' } });
});

describe('the copilot suggestions', () => {
  it('name no invented host or person, in the prompts or in the input hint', () => {
    const { container } = render(<CopilotView />);
    expect(container.textContent).not.toMatch(INVENTED_ASSET);
    expect(screen.getByPlaceholderText(/Ask anything/).getAttribute('placeholder')).not.toMatch(INVENTED_ASSET);
  });

  it('still offer an entity investigation, and the input hint still shows the pattern generically', () => {
    render(<CopilotView />);
    expect(screen.getAllByText('Investigate an entity').length).toBeGreaterThan(0); // in the sidebar list and the empty-state grid
    expect(screen.getByPlaceholderText(/Ask anything/).getAttribute('placeholder')).toContain('investigate <hostname>');
  });

  it('send, when clicked, an investigation prompt with no invented asset, no raw template, and a way out if nothing is risky', async () => {
    render(<CopilotView />);
    await userEvent.setup().click(screen.getAllByRole('button', { name: /Investigate an entity/ })[0]);
    await vi.waitFor(() => expect(copilotApi.chat).toHaveBeenCalled());
    const sent = JSON.stringify(copilotApi.chat.mock.calls[0]);
    expect(sent).toMatch(/Investigate the highest-risk host or user/);
    expect(sent).not.toMatch(INVENTED_ASSET);
    expect(sent).not.toContain('<hostname>'); // a template is a hint for typing, never something to send raw
    expect(sent).toMatch(/If nothing is currently high risk, say so/);
  });
});
