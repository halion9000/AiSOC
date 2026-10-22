import { describe, expect, it } from 'vitest';
import { render, screen } from '@testing-library/react';
import VendorBadge, { orderSources, VENDOR_ORDER } from './VendorBadge';

describe('orderSources', () => {
  it('puts Halo first and the rest in one fixed order, so every row lines up', () => {
    expect(orderSources(['fieldeffect', 'huntress', 'halopsa', 'ninjaone'])).toEqual(['halopsa', 'ninjaone', 'huntress', 'fieldeffect']);
  });

  it('lists a tool it does not know after the known ones, alphabetically, and drops repeats', () => {
    expect(orderSources(['zeta', 'ninjaone', 'alpha', 'ninjaone'])).toEqual(['ninjaone', 'alpha', 'zeta']);
  });

  it('knows every tool CORE feeds', () => {
    for (const v of ['huntress', 'blumira', 'petra', 'ninjaone', 'threatmate', 'addigy', 'fieldeffect', 'dnsfilter', 'autoelevate']) expect(VENDOR_ORDER).toContain(v);
  });
});

describe('VendorBadge', () => {
  it('shows the tool logo with its full name for a known tool', () => {
    render(<VendorBadge vendor="fieldeffect" />);
    const img = screen.getByAltText('Field Effect') ?? screen.getByAltText('Fieldeffect');
    expect(img).toHaveAttribute('src', '/vendors/fieldeffect.png');
  });

  it('falls back to a lettered badge, named for screen readers, for a tool with no logo', () => {
    render(<VendorBadge vendor="widgetco" />);
    const badge = screen.getByRole('img', { name: 'Widgetco' });
    expect(badge).toHaveTextContent('W');
  });

  it('is larger when asked', () => {
    render(<VendorBadge vendor="widgetco" size="lg" />);
    expect(screen.getByRole('img', { name: 'Widgetco' }).className).toMatch(/h-10/);
  });
});

describe('CIPP logo', () => {
  it('shows its logo file, named CIPP, and sorts after AutoElevate', () => {
    render(<VendorBadge vendor="cipp" />);
    expect(screen.getByAltText('CIPP')).toHaveAttribute('src', '/vendors/cipp.png');
    expect(orderSources(['cipp', 'autoelevate', 'huntress'])).toEqual(['huntress', 'autoelevate', 'cipp']);
  });
});

describe('DNSFilter and AutoElevate logos', () => {
  it('show their logo files, named in full', () => {
    render(
      <>
        <VendorBadge vendor="dnsfilter" />
        <VendorBadge vendor="autoelevate" />
      </>,
    );
    expect(screen.getByAltText('DNSFilter')).toHaveAttribute('src', '/vendors/dnsfilter.png');
    expect(screen.getByAltText('AutoElevate')).toHaveAttribute('src', '/vendors/autoelevate.png');
  });

  it('sort after Field Effect, DNSFilter before AutoElevate', () => {
    expect(orderSources(['autoelevate', 'dnsfilter', 'huntress', 'fieldeffect'])).toEqual(['huntress', 'fieldeffect', 'dnsfilter', 'autoelevate']);
  });
});

describe('the ScreenConnect badge', () => {
  it('shows its own logo image, not the SC letters', () => {
    const { container } = render(<VendorBadge vendor="screenconnect" />);
    const img = container.querySelector('img');
    expect(img).not.toBeNull();
    expect(img?.getAttribute('src')).toBe('/vendors/screenconnect.png');
    expect(img?.getAttribute('alt')).toBe('ScreenConnect');
  });
});

describe('the vCIO Toolbox badge', () => {
  it('shows its own logo image, named vCIO Toolbox', () => {
    const { container } = render(<VendorBadge vendor="vciotoolbox" />);
    const img = container.querySelector('img');
    expect(img?.getAttribute('src')).toBe('/vendors/vciotoolbox.png');
    expect(img?.getAttribute('alt')).toBe('vCIO Toolbox');
  });
});
