import { describe, expect, it } from 'vitest';
import { fireEvent, render, screen } from '@testing-library/react';
import { vi } from 'vitest';

import { TicketRows } from './AlertContext';

describe('TicketRows', () => {
  it('shows what A.C.O.R.N was told, and says a hand-added ticket has no summary because A.C.O.R.N cannot read HaloPSA', () => {
    render(<TicketRows tickets={[{ id: '4521', system: 'halopsa', summary: 'Disk full', status: 'Open' }, { id: '555871', system: 'halopsa', manual: true }]} />);
    expect(screen.getByText(/Disk full/)).toBeInTheDocument();
    expect(screen.getByText(/Linked by hand/)).toBeInTheDocument();
    expect(screen.queryByText(/Not found in HaloPSA/)).toBeNull();
  });

  it('still says not found for a ticket CORE looked up and Halo did not know', () => {
    render(<TicketRows tickets={[{ id: '999', system: 'halopsa' }]} />);
    expect(screen.getByText(/Not found in HaloPSA/)).toBeInTheDocument();
  });

  it('offers Remove for a ticket Halo no longer has, but not for one Halo still knows', () => {
    const onRemove = vi.fn();
    render(<TicketRows onRemove={onRemove} tickets={[{ id: '100', system: 'halopsa', summary: 'Disk full' }, { id: '555709', system: 'halopsa' }]} />);
    expect(screen.queryByLabelText('Remove ticket 100')).toBeNull();
    fireEvent.click(screen.getByLabelText('Remove ticket 555709'));
    expect(onRemove).toHaveBeenCalledWith('555709');
    expect(screen.getByText(/deleted or merged/)).toBeInTheDocument();
  });
});
