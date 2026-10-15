import { describe, expect, it, vi } from 'vitest';
import { render } from '@testing-library/react';

let path = '/detection/vendor-detections';
vi.mock('next/navigation', () => ({ usePathname: () => path }));
vi.mock('next/link', () => ({
  default: ({ children, href, className }: { children: React.ReactNode; href: string; className?: string }) => (
    <a href={href} className={className}>
      {children}
    </a>
  ),
}));

import { Sidebar } from './Sidebar';

/** hrefs of the links drawn as active (the active style carries the brand border). */
function activeHrefs(): string[] {
  const { container, unmount } = render(<Sidebar />);
  const out = [...container.querySelectorAll('a')].filter((a) => a.className.includes('border-brand-600/20')).map((a) => a.getAttribute('href') as string);
  unmount();
  return out;
}

describe('Sidebar active link', () => {
  it('lights up only the most specific link, not Detection Rules as well', () => {
    path = '/detection/vendor-detections';
    expect(activeHrefs()).toEqual(['/detection/vendor-detections']);
    path = '/detection/coverage';
    expect(activeHrefs()).toEqual(['/detection/coverage']);
  });

  it('still lights up a parent link on its own page and on a sub-page without its own link', () => {
    path = '/detection';
    expect(activeHrefs()).toEqual(['/detection']);
    path = '/detection/some-new-page';
    expect(activeHrefs()).toEqual(['/detection']);
  });
});
