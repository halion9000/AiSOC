import { describe, expect, it } from 'vitest';
import { render, screen } from '@testing-library/react';

import VendorBadge, { orderSources } from './VendorBadge';

describe('Auvik in the vendor badges', () => {
  it('sorts after DNSFilter and before AutoElevate, in the fixed order every row uses', () => {
    expect(orderSources(['autoelevate', 'auvik', 'dnsfilter', 'halopsa'])).toEqual(['halopsa', 'dnsfilter', 'auvik', 'autoelevate']);
  });

  it('shows its logo rather than the fallback', () => {
    const { container } = render(<VendorBadge vendor="auvik" />);
    expect(container.querySelector('img')?.getAttribute('src')).toBe('/vendors/auvik.png');
    expect(screen.queryByText('?')).toBeNull();
  });
});
