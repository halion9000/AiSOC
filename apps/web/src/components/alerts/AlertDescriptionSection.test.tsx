import { describe, expect, it } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { AlertDescriptionSection, DESCRIPTION_PREVIEW_CHARS } from './AlertDescriptionSection';

describe('AlertDescriptionSection', () => {
  it('shows a short description in full, keeping its line breaks', () => {
    render(<AlertDescriptionSection description={'Line one\nLine two'} />);
    const p = screen.getByText(/Line one/);
    expect(p.textContent).toBe('Line one\nLine two');
    expect(p.className).toMatch(/whitespace-pre-wrap/);
    expect(screen.queryByRole('button')).toBeNull();
  });

  it('folds a long write-up and unfolds it on request', async () => {
    const text = 'x'.repeat(DESCRIPTION_PREVIEW_CHARS + 500);
    render(<AlertDescriptionSection description={text} />);
    expect(screen.getByText(/^x+…$/).textContent!.length).toBeLessThan(text.length);
    await userEvent.click(screen.getByRole('button', { name: 'Show more' }));
    expect(screen.getByText(text)).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'Show less' }));
    expect(screen.getByText(/^x+…$/)).toBeInTheDocument();
  });

  it('renders nothing when there is nothing to read', () => {
    const a = render(<AlertDescriptionSection description={null} />);
    expect(a.container).toBeEmptyDOMElement();
    const b = render(<AlertDescriptionSection description={'   '} />);
    expect(b.container).toBeEmptyDOMElement();
  });
});
