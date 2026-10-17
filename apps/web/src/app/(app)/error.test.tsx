import { fireEvent, render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import AppError from './error';
import RootError from '../error';

describe('route error boundaries', () => {
  it.each([
    ['the app segment', AppError],
    ['the root', RootError],
  ])('%s shows a recoverable error instead of a blank page', (_name, Boundary) => {
    const reset = vi.fn();
    const error = Object.assign(new Error('Invalid time value'), { digest: 'abc123' });
    render(<Boundary error={error} reset={reset} />);
    expect(screen.getByRole('alert')).toBeInTheDocument();
    expect(screen.getByText(/Invalid time value/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: /retry/i }));
    expect(reset).toHaveBeenCalledTimes(1);
  });
});
