import { describe, expect, it } from 'vitest';
import { render, screen } from '@testing-library/react';

import VendorBadge, { orderSources } from './VendorBadge';

describe('Auvik in the vendor badges', () => {
  it('sorts after DNSFilter and before AutoElevate, in the fixed order every row uses', () => {
    expect(orderSources(['autoelevate', 'auvik', 'dnsfilter', 'halopsa'])).toEqual(['halopsa', 'dnsfilter', 'auvik', 'autoelevate']);
  });

  it('has a badge of its own rather than the fallback', () => {
    const { container } = render(<VendorBadge vendor="auvik" />);
    expect(container.textContent).toContain('Av');
    expect(screen.queryByText('?')).toBeNull();
  });
});
