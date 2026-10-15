'use client';

import clsx from 'clsx';
import { formatDistanceToNow } from 'date-fns';
import type { FimEvent } from '@/lib/osquery-api';

interface Props {
  events: FimEvent[];
  total: number;
  page: number;
  pageSize: number;
  onPageChange: (page: number) => void;
}

const ACTION_BADGE: Record<string, string> = {
  CREATED: 'bg-emerald-100 text-emerald-700',
  DELETED: 'bg-red-500/20 text-red-300',
  UPDATED: 'bg-amber-500/20 text-amber-300',
  ATTRIBUTES_MODIFIED: 'bg-sky-100 text-sky-700',
};

export function FimEventsTable({ events, total, page, pageSize, onPageChange }: Props) {
  const totalPages = Math.max(1, Math.ceil(total / pageSize));

  if (events.length === 0) {
    return (
      <div className="rounded-xl border border-gray-800 bg-gray-900/60 p-10 text-center">
        <p className="text-sm text-gray-500">No FIM events found for the selected filters.</p>
      </div>
    );
  }

  return (
    <div className="space-y-2">
      <div className="overflow-hidden rounded-xl border border-gray-800 bg-gray-900/60 shadow-sm">
        <table className="min-w-full divide-y divide-gray-800 text-sm">
          <thead className="bg-gray-900/40">
            <tr>
              <Th>Time</Th>
              <Th>Action</Th>
              <Th>Path</Th>
              <Th>Host</Th>
              <Th>Process</Th>
              <Th>User</Th>
              <Th>SHA-256</Th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-800/60 bg-gray-900/60">
            {events.map((e) => (
              <tr key={e.id} className="hover:bg-gray-800/60">
                <Td>
                  <span
                    title={e.event_time}
                    className="whitespace-nowrap text-gray-500"
                  >
                    {formatDistanceToNow(new Date(e.event_time), { addSuffix: true })}
                  </span>
                </Td>
                <Td>
                  <span
                    className={clsx(
                      'rounded-full px-2 py-0.5 text-xs font-semibold',
                      ACTION_BADGE[e.action] ?? 'bg-gray-800 text-gray-400',
                    )}
                  >
                    {e.action}
                  </span>
                </Td>
                <Td>
                  <span className="max-w-[260px] truncate font-mono text-xs text-gray-100 block">
                    {e.target_path}
                  </span>
                </Td>
                <Td>{e.hostname ?? e.node_key.slice(0, 8)}</Td>
                <Td>
                  {e.process_name ? (
                    <span className="font-mono text-xs">
                      {e.process_name}
                      {e.pid != null && (
                        <span className="ml-1 text-gray-400">({e.pid})</span>
                      )}
                    </span>
                  ) : (
                    <span className="text-gray-400">—</span>
                  )}
                </Td>
                <Td>{e.username ?? <span className="text-gray-400">—</span>}</Td>
                <Td>
                  {e.sha256 ? (
                    <span
                      title={e.sha256}
                      className="font-mono text-xs text-gray-500"
                    >
                      {e.sha256.slice(0, 12)}…
                    </span>
                  ) : (
                    <span className="text-gray-400">—</span>
                  )}
                </Td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Pagination */}
      <div className="flex items-center justify-between text-sm text-gray-400">
        <span>
          Showing {(page - 1) * pageSize + 1}–
          {Math.min(page * pageSize, total)} of {total.toLocaleString()} events
        </span>
        <div className="flex items-center gap-2">
          <PaginationButton
            label="← Prev"
            disabled={page <= 1}
            onClick={() => onPageChange(page - 1)}
          />
          <span className="text-xs text-gray-500">
            Page {page} / {totalPages}
          </span>
          <PaginationButton
            label="Next →"
            disabled={page >= totalPages}
            onClick={() => onPageChange(page + 1)}
          />
        </div>
      </div>
    </div>
  );
}

function Th({ children }: { children: React.ReactNode }) {
  return (
    <th className="px-3 py-2.5 text-left text-xs font-semibold uppercase tracking-wider text-gray-500">
      {children}
    </th>
  );
}

function Td({ children }: { children: React.ReactNode }) {
  return <td className="px-3 py-2.5 text-gray-300">{children}</td>;
}

function PaginationButton({
  label,
  disabled,
  onClick,
}: {
  label: string;
  disabled: boolean;
  onClick: () => void;
}) {
  return (
    <button
      onClick={onClick}
      disabled={disabled}
      className={clsx(
        'rounded px-3 py-1 text-xs font-medium transition',
        disabled
          ? 'cursor-not-allowed text-gray-300'
          : 'bg-gray-800 text-gray-300 hover:bg-gray-700',
      )}
    >
      {label}
    </button>
  );
}
