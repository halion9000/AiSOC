import { describe, expect, it, vi, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { axe } from 'vitest-axe';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { TenantViewBanner } from './TenantViewBanner';

const tenantState = vi.fn();
vi.mock('./TenantProvider', () => ({ useTenant: () => tenantState() }));

const parent = { id: 'p', name: 'MSSP Holdings', relationship: 'self', access: 'full' };
const customer = { id: 'c1', name: 'Customer A', relationship: 'granted', access: 'view' };
const customerFull = { id: 'c1', name: 'Customer A', relationship: 'granted', access: 'full' };
const customerUnknown = { id: 'c1', name: 'Customer A', relationship: 'granted', access: null };
const returnToHome = vi.fn();

beforeEach(() => {
  returnToHome.mockReset();
  tenantState.mockReset();
});

describe('TenantViewBanner', () => {
  it('shows nothing while the person is on their own tenant', () => {
    tenantState.mockReturnValue({ current: parent, home: parent, viewingOther: false, returnToHome });
    const { container } = render(<TenantViewBanner />);
    expect(container).toBeEmptyDOMElement();
  });

  it('shows nothing before the tenant is known', () => {
    tenantState.mockReturnValue({ current: null, home: null, viewingOther: false, returnToHome });
    const { container } = render(<TenantViewBanner />);
    expect(container).toBeEmptyDOMElement();
  });

  it('shows nothing when viewingOther is true but there is no current tenant to name', () => {
    tenantState.mockReturnValue({ current: null, home: parent, viewingOther: true, returnToHome });
    const { container } = render(<TenantViewBanner />);
    expect(container).toBeEmptyDOMElement();
  });

  it('says whose data this is and that it is read-only', () => {
    tenantState.mockReturnValue({ current: customer, home: parent, viewingOther: true, returnToHome });
    render(<TenantViewBanner />);
    const banner = screen.getByRole('status');
    expect(banner).toHaveTextContent('Viewing Customer A.');
    expect(banner).toHaveTextContent(/read-only/i);
    expect(banner).toHaveTextContent(/not change it/i);
  });

  it('offers the way back, named for the person\'s own tenant, and takes it', async () => {
    tenantState.mockReturnValue({ current: customer, home: parent, viewingOther: true, returnToHome });
    render(<TenantViewBanner />);
    await userEvent.click(screen.getByRole('button', { name: 'Return to MSSP Holdings' }));
    expect(returnToHome).toHaveBeenCalledTimes(1);
  });

  it('still offers the way back when the own tenant\'s name is not known', () => {
    tenantState.mockReturnValue({ current: customer, home: null, viewingOther: true, returnToHome });
    render(<TenantViewBanner />);
    expect(screen.getByRole('button', { name: 'Return to your tenant' })).toBeInTheDocument();
  });

  it('with FULL access says the person is WORKING there, that changes are made in that tenant and recorded in its audit log, and never calls it read-only', () => {
    tenantState.mockReturnValue({ current: customerFull, home: parent, viewingOther: true, returnToHome });
    render(<TenantViewBanner />);
    const banner = screen.getByRole('status');
    expect(banner).toHaveTextContent('Working in Customer A with full access.');
    expect(banner).toHaveTextContent(/recorded in its audit log/i);
    expect(banner).not.toHaveTextContent(/read-only/i);
    expect(banner).not.toHaveTextContent(/Viewing/);
    expect(banner).toHaveAttribute('data-access', 'full');
  });

  it('looks different when working (red) from when viewing (amber), so the two cannot be mistaken for each other', () => {
    tenantState.mockReturnValue({ current: customerFull, home: parent, viewingOther: true, returnToHome });
    const { unmount } = render(<TenantViewBanner />);
    expect(screen.getByRole('status').className).toMatch(/red-500/);
    expect(screen.getByRole('status').className).not.toMatch(/amber/);
    unmount();
    tenantState.mockReturnValue({ current: customer, home: parent, viewingOther: true, returnToHome });
    render(<TenantViewBanner />);
    expect(screen.getByRole('status').className).toMatch(/amber-500/);
    expect(screen.getByRole('status').className).not.toMatch(/red-500/);
    expect(screen.getByRole('status')).toHaveAttribute('data-access', 'view');
  });

  it('when the level is not known it says only whose tenant this is, claiming neither read-only nor full access', () => {
    tenantState.mockReturnValue({ current: customerUnknown, home: parent, viewingOther: true, returnToHome });
    render(<TenantViewBanner />);
    const banner = screen.getByRole('status');
    expect(banner).toHaveTextContent('Viewing Customer A.');
    expect(banner).not.toHaveTextContent(/read-only/i);
    expect(banner).not.toHaveTextContent(/Working/);
    expect(banner).toHaveAttribute('data-access', 'unknown');
  });

  it('offers the way back in the working state too, and takes it', async () => {
    tenantState.mockReturnValue({ current: customerFull, home: parent, viewingOther: true, returnToHome });
    render(<TenantViewBanner />);
    await userEvent.click(screen.getByRole('button', { name: 'Return to MSSP Holdings' }));
    expect(returnToHome).toHaveBeenCalledTimes(1);
  });

  it('has no accessibility violations while working either', async () => {
    tenantState.mockReturnValue({ current: customerFull, home: parent, viewingOther: true, returnToHome });
    const { container } = render(<TenantViewBanner />);
    const results = await axe(container, { rules: { 'color-contrast': { enabled: false } } });
    expect(results).toHaveNoViolations();
  });

  it('is announced politely, not as an alert that interrupts', () => {
    tenantState.mockReturnValue({ current: customer, home: parent, viewingOther: true, returnToHome });
    render(<TenantViewBanner />);
    expect(screen.getByRole('status')).toHaveAttribute('aria-live', 'polite');
  });

  it('has no accessibility violations', async () => {
    tenantState.mockReturnValue({ current: customer, home: parent, viewingOther: true, returnToHome });
    const { container } = render(<TenantViewBanner />);
    const results = await axe(container, { rules: { 'color-contrast': { enabled: false } } });
    expect(results).toHaveNoViolations();
  });
});

describe('the banner is on every page', () => {
  it('is mounted by the app shell, inside the tenant provider, above the page content', () => {
    const src = readFileSync(resolve(__dirname, 'AppShell.tsx'), 'utf8');
    const provider = src.indexOf('<TenantProvider>');
    const banner = src.indexOf('<TenantViewBanner />');
    const content = src.indexOf('{children}');
    expect(provider).toBeGreaterThan(-1);
    expect(banner).toBeGreaterThan(provider);
    expect(content).toBeGreaterThan(banner);
    expect(src.indexOf('</TenantProvider>')).toBeGreaterThan(banner);
  });
});
