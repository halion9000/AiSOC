import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

// The picker offers only what the server listed (GET /tenants/selectable) and only if the server says this user may look at other tenants.
const hook = vi.hoisted(() => ({ value: { data: undefined } as { data?: unknown } }));
vi.mock('@/hooks/useSelectableTenants', () => ({ useSelectableTenants: () => hook.value }));

import { TenantScopePicker } from './TenantScopePicker';

const OWN = 'tenant-own';
const tenants = [
  { id: 'tenant-b', name: 'Bravo Corp', slug: 'bravo' },
  { id: OWN, name: 'Home MSP', slug: 'home' },
  { id: 'tenant-c', name: 'Charlie LLC', slug: 'charlie' },
];
const holder = { own_tenant_id: OWN, can_select_other_tenants: true, tenants };
const select = () => screen.getByRole('combobox', { name: /Tenant/ });

beforeEach(() => {
  hook.value = { data: holder };
});

describe('when there is nothing real to choose, it renders nothing', () => {
  it('while the list is still loading', () => {
    hook.value = { data: undefined };
    const { container } = render(<TenantScopePicker value={null} onChange={vi.fn()} />);
    expect(container).toBeEmptyDOMElement();
  });

  it('for a user the server says may not look at other tenants, even if several are listed', () => {
    hook.value = { data: { ...holder, can_select_other_tenants: false } };
    const { container } = render(<TenantScopePicker value={null} onChange={vi.fn()} />);
    expect(container).toBeEmptyDOMElement();
  });

  it('when only their own tenant is listed', () => {
    hook.value = { data: { own_tenant_id: OWN, can_select_other_tenants: true, tenants: [tenants[1]] } };
    const { container } = render(<TenantScopePicker value={null} onChange={vi.fn()} />);
    expect(container).toBeEmptyDOMElement();
  });
});

describe('for someone who may look at other tenants', () => {
  it('lists their own tenant first, marked, then the others in the order given, and defaults to their own', () => {
    render(<TenantScopePicker value={null} onChange={vi.fn()} />);
    const options = screen.getAllByRole('option').map((o) => o.textContent);
    expect(options).toEqual(['Home MSP (your tenant)', 'Bravo Corp', 'Charlie LLC']);
    expect(select()).toHaveValue(OWN);
  });

  it('choosing another tenant reports its id', async () => {
    const onChange = vi.fn();
    render(<TenantScopePicker value={null} onChange={onChange} />);
    await userEvent.setup().selectOptions(select(), 'Charlie LLC');
    expect(onChange).toHaveBeenCalledExactlyOnceWith('tenant-c');
  });

  it('choosing their own tenant again CLEARS the selection (null) rather than naming it', async () => {
    const onChange = vi.fn();
    render(<TenantScopePicker value="tenant-b" onChange={onChange} />);
    await userEvent.setup().selectOptions(select(), 'Home MSP (your tenant)');
    expect(onChange).toHaveBeenCalledExactlyOnceWith(null);
  });

  it('shows the selected tenant in the control', () => {
    render(<TenantScopePicker value="tenant-b" onChange={vi.fn()} />);
    expect(select()).toHaveValue('tenant-b');
  });

  it('while another tenant is selected it SAYS whose data this is, read-only, with a way back', async () => {
    const onChange = vi.fn();
    render(<TenantScopePicker value="tenant-b" onChange={onChange} />);
    expect(screen.getByRole('status')).toHaveTextContent("Viewing Bravo Corp's data (read-only).");
    await userEvent.setup().click(screen.getByRole('button', { name: 'Back to my tenant' }));
    expect(onChange).toHaveBeenCalledExactlyOnceWith(null);
  });

  it('shows no such note for their own tenant, whether unset or named', () => {
    const { rerender } = render(<TenantScopePicker value={null} onChange={vi.fn()} />);
    expect(screen.queryByRole('status')).not.toBeInTheDocument();
    rerender(<TenantScopePicker value={OWN} onChange={vi.fn()} />);
    expect(screen.queryByRole('status')).not.toBeInTheDocument();
  });

  it('uses the label it is given', () => {
    render(<TenantScopePicker value={null} onChange={vi.fn()} label="Customer" />);
    expect(screen.getByRole('combobox', { name: /Customer/ })).toBeInTheDocument();
  });

  it('styles itself for the dark and the light surfaces', () => {
    const { rerender } = render(<TenantScopePicker value={null} onChange={vi.fn()} />);
    expect(select().className).toContain('bg-gray-900');
    rerender(<TenantScopePicker value={null} onChange={vi.fn()} tone="light" />);
    expect(select().className).toContain('bg-white');
  });
});

describe('a selection the server no longer lists', () => {
  it('is dropped (null) so the view falls back to the caller\'s own tenant', () => {
    const onChange = vi.fn();
    render(<TenantScopePicker value="tenant-gone" onChange={onChange} />);
    expect(onChange).toHaveBeenCalledExactlyOnceWith(null);
  });

  it('is kept while the list is still loading (nothing is known yet)', () => {
    hook.value = { data: undefined };
    const onChange = vi.fn();
    render(<TenantScopePicker value="tenant-b" onChange={onChange} />);
    expect(onChange).not.toHaveBeenCalled();
  });

  it('is dropped when the user lost the permission (the server now says they may not)', () => {
    hook.value = { data: { own_tenant_id: OWN, can_select_other_tenants: false, tenants: [tenants[1]] } };
    const onChange = vi.fn();
    render(<TenantScopePicker value="tenant-b" onChange={onChange} />);
    expect(onChange).toHaveBeenCalledExactlyOnceWith(null);
  });

  it('does not fire for a selection that IS listed', () => {
    const onChange = vi.fn();
    render(<TenantScopePicker value="tenant-b" onChange={onChange} />);
    expect(onChange).not.toHaveBeenCalled();
  });
});
