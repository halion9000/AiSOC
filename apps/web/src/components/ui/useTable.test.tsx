import { describe, expect, it } from 'vitest';
import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import { FilterRow, SortableTh, applyTable, compareValues, useTable, type Column } from './useTable';

interface Row {
  name: string;
  n: number | null;
  kind: string;
  at: string | null;
}

const ROWS: Row[] = [
  { name: 'beta', n: 5, kind: 'a', at: '2026-10-02T00:00:00Z' },
  { name: 'Alpha', n: 20, kind: 'b', at: '2026-10-03T00:00:00Z' },
  { name: 'gamma10', n: null, kind: 'a', at: null },
  { name: 'gamma2', n: 1, kind: 'b', at: '2026-10-01T00:00:00Z' },
];

const COLS: Column<Row>[] = [
  { key: 'name', label: 'Name', value: (r) => r.name, filter: 'text' },
  { key: 'n', label: 'Count', value: (r) => r.n, filter: 'min', align: 'right' },
  { key: 'kind', label: 'Kind', value: (r) => r.kind, filter: 'choice' },
  { key: 'at', label: 'When', value: (r) => r.at, sortValue: (r) => (r.at ? Date.parse(r.at) : null), filter: 'none' },
];

const names = (rows: Row[]) => rows.map((r) => r.name);

describe('compareValues', () => {
  it('orders numbers by value, text by letters with digits in order, and empty last', () => {
    expect(compareValues(2, 10)).toBeLessThan(0);
    expect(compareValues('gamma2', 'gamma10')).toBeLessThan(0);
    expect(compareValues('alpha', 'Beta')).toBeLessThan(0);
    expect(compareValues(null, 1)).toBeGreaterThan(0);
    expect(compareValues(null, null)).toBe(0);
  });
});

describe('applyTable', () => {
  it('sorts ascending and descending and keeps empty values last either way', () => {
    expect(names(applyTable(ROWS, COLS, {}, { key: 'n', dir: 'asc' }))).toEqual(['gamma2', 'beta', 'Alpha', 'gamma10']);
    expect(names(applyTable(ROWS, COLS, {}, { key: 'n', dir: 'desc' }))).toEqual(['Alpha', 'beta', 'gamma2', 'gamma10']);
  });
  it('sorts by the sort value when it differs from what is shown', () => {
    expect(names(applyTable(ROWS, COLS, {}, { key: 'at', dir: 'asc' }))).toEqual(['gamma2', 'beta', 'Alpha', 'gamma10']);
  });
  it('filters text by contains, ignoring case', () => {
    expect(names(applyTable(ROWS, COLS, { name: 'GAM' }, null))).toEqual(['gamma10', 'gamma2']);
  });
  it('filters a number column by minimum and drops rows with no number', () => {
    expect(names(applyTable(ROWS, COLS, { n: '5' }, null))).toEqual(['beta', 'Alpha']);
    expect(names(applyTable(ROWS, COLS, { n: 'abc' }, null))).toHaveLength(4);
  });
  it('filters a choice column by the exact value, and filters combine', () => {
    expect(names(applyTable(ROWS, COLS, { kind: 'a' }, null))).toEqual(['beta', 'gamma10']);
    expect(names(applyTable(ROWS, COLS, { kind: 'a', name: 'beta' }, null))).toEqual(['beta']);
    expect(names(applyTable(ROWS, COLS, { name: '   ' }, null))).toHaveLength(4);
  });
  it('does not change the rows it was given', () => {
    const before = names(ROWS);
    applyTable(ROWS, COLS, {}, { key: 'name', dir: 'desc' });
    expect(names(ROWS)).toEqual(before);
  });
});

function Demo() {
  const t = useTable(ROWS, COLS);
  return (
    <table>
      <thead>
        <tr>
          {COLS.map((c) => (
            <SortableTh key={c.key} col={c} sort={t.sort} onSort={t.toggleSort} />
          ))}
        </tr>
        <FilterRow columns={COLS} filters={t.filters} setFilter={t.setFilter} choices={t.choices} />
      </thead>
      <tbody>
        {t.shown.map((r) => (
          <tr key={r.name} data-testid="row">
            <td>{r.name}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

const order = () => screen.getAllByTestId('row').map((r) => r.textContent);

describe('the table controls', () => {
  it('sorts when a header is clicked, reverses on the second click and clears on the third', async () => {
    render(<Demo />);
    const th = screen.getByRole('columnheader', { name: /Count/ });
    expect(th).toHaveAttribute('aria-sort', 'none');
    await userEvent.click(within(th).getByRole('button'));
    expect(th).toHaveAttribute('aria-sort', 'ascending');
    expect(order()).toEqual(['gamma2', 'beta', 'Alpha', 'gamma10']);
    await userEvent.click(within(th).getByRole('button'));
    expect(th).toHaveAttribute('aria-sort', 'descending');
    expect(order()).toEqual(['Alpha', 'beta', 'gamma2', 'gamma10']);
    await userEvent.click(within(th).getByRole('button'));
    expect(th).toHaveAttribute('aria-sort', 'none');
    expect(order()).toEqual(['beta', 'Alpha', 'gamma10', 'gamma2']);
  });

  it('filters by a typed box, a menu of the values present and a minimum', async () => {
    render(<Demo />);
    await userEvent.type(screen.getByLabelText('Filter Name'), 'gamma');
    expect(order()).toEqual(['gamma10', 'gamma2']);
    await userEvent.selectOptions(screen.getByLabelText('Filter Kind'), 'b');
    expect(order()).toEqual(['gamma2']);
    expect(within(screen.getByLabelText('Filter Kind')).getAllByRole('option').map((o) => o.textContent)).toEqual(['All', 'a', 'b']);
    await userEvent.clear(screen.getByLabelText('Filter Name'));
    await userEvent.type(screen.getByLabelText('Minimum Count'), '10');
    expect(order()).toEqual(['Alpha']);
  });
});
