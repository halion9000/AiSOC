import { describe, expect, it } from 'vitest';
import { render, screen } from '@testing-library/react';

import { TicketRows } from './AlertContext';

describe('TicketRows', () => {
  it('shows what AiSOC was told, and says a hand-added ticket has no summary because AiSOC cannot read HaloPSA', () => {
    render(<TicketRows tickets={[{ id: '4521', system: 'halopsa', summary: 'Disk full', status: 'Open' }, { id: '555871', system: 'halopsa', manual: true }]} />);
    expect(screen.getByText(/Disk full/)).toBeInTheDocument();
    expect(screen.getByText(/Linked by hand/)).toBeInTheDocument();
    expect(screen.queryByText(/Not found in HaloPSA/)).toBeNull();
  });

  it('still says not found for a ticket CORE looked up and Halo did not know', () => {
    render(<TicketRows tickets={[{ id: '999', system: 'halopsa' }]} />);
    expect(screen.getByText(/Not found in HaloPSA/)).toBeInTheDocument();
  });
});
