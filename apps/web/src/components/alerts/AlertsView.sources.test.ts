import { describe, expect, it } from 'vitest';
import { sourceOptions } from './AlertsView';

const feed = (name: string, vendor?: string) => ({ type: 'core_feed', name, config: vendor ? { vendor, managed_by: 'core' } : {} });

describe('the Source filter options', () => {
  it('offers one entry per CORE-fed tool, named without the "(via CORE)" suffix, sorted by name', () => {
    const options = sourceOptions([feed('Petra MDR (via CORE)', 'petra'), feed('Huntress (via CORE)', 'huntress')]);
    expect(options).toEqual([
      { vendor: 'huntress', label: 'Huntress' },
      { vendor: 'petra', label: 'Petra MDR' },
    ]);
  });

  it('ignores connectors that are not CORE feeds and feeds that name no tool', () => {
    expect(sourceOptions([{ type: 'okta', name: 'Okta', config: { vendor: 'okta' } }, feed('Mystery (via CORE)')])).toEqual([]);
  });

  it('lists a tool once even if it has two rows', () => {
    expect(sourceOptions([feed('Huntress (via CORE)', 'huntress'), feed('Huntress again (via CORE)', 'huntress')])).toHaveLength(1);
  });
});
