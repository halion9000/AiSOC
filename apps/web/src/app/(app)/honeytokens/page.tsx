"use client";

import { useState } from "react";
import useSWR, { mutate } from "swr";
import { authFetch } from "@/lib/auth-session";
import { TOKEN_TYPES, TOKEN_TYPE_ORDER, canAlert, plantables, type HoneytokenRecord, type TokenStatus } from "./tokens";

// Same-origin by default — Next.js rewrites proxy `/api/v1/honeytokens/*`
// to the honeytokens service. Override with `NEXT_PUBLIC_HONEYTOKENS_URL`
// to debug against a different origin.
const API = process.env.NEXT_PUBLIC_HONEYTOKENS_URL ?? "";
const TENANT_ID = process.env.NEXT_PUBLIC_TENANT_ID ?? "00000000-0000-0000-0000-000000000001";

const fetcher = (url: string) =>
  authFetch(url).then((r) => {
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    return r.json();
  });

interface Trigger {
  id: string;
  source_ip: string | null;
  user_agent: string | null;
  threat_score: number | null;
  alert_sent: boolean;
  triggered_at: string;
}

const STATUS_COLORS: Record<TokenStatus, string> = {
  active: "bg-green-900/40 text-green-300",
  triggered: "bg-red-900/40 text-red-300",
  expired: "bg-gray-800 text-gray-400",
  revoked: "bg-yellow-900/40 text-yellow-300",
};

function TokenRow({
  token,
  onRevoke,
  onDelete,
  onSelect,
}: {
  token: HoneytokenRecord;
  onRevoke: (id: string) => void;
  onDelete: (id: string) => void;
  onSelect: (id: string) => void;
}) {
  const alerts = canAlert(token);
  return (
    <tr className="hover:bg-gray-800/50 cursor-pointer" onClick={() => onSelect(token.id)}>
      <td className="px-4 py-3 text-sm font-medium text-gray-100 max-w-xs truncate">{token.name}</td>
      <td className="px-4 py-3 text-sm text-gray-400">{TOKEN_TYPES[token.token_type]?.label ?? token.token_type}</td>
      <td className="px-4 py-3 text-xs">
        <span className={alerts ? "text-green-300" : "text-gray-500"}>{alerts ? "Alerts when opened" : "Decoy only"}</span>
      </td>
      <td className="px-4 py-3">
        <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium ${STATUS_COLORS[token.status]}`}>{token.status}</span>
      </td>
      <td className="px-4 py-3 text-sm text-gray-500" suppressHydrationWarning>
        {token.expires_at ? new Date(token.expires_at).toLocaleDateString() : "—"}
      </td>
      <td className="px-4 py-3 text-sm" onClick={(e) => e.stopPropagation()}>
        <div className="flex gap-2">
          <button onClick={() => onSelect(token.id)} className="text-blue-400 hover:text-blue-300 text-xs">
            Details
          </button>
          {token.status === "active" && (
            <button onClick={() => onRevoke(token.id)} className="text-yellow-400 hover:text-yellow-300 text-xs">
              Revoke
            </button>
          )}
          <button onClick={() => onDelete(token.id)} className="text-red-400 hover:text-red-300 text-xs">
            Delete
          </button>
        </div>
      </td>
    </tr>
  );
}

function CreateTokenModal({ onClose, onCreate }: { onClose: () => void; onCreate: (created: HoneytokenRecord | null) => void }) {
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [tokenType, setTokenType] = useState("url");
  const [ttlDays, setTtlDays] = useState(365);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const submit = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await authFetch(`${API}/api/v1/honeytokens`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ tenant_id: TENANT_ID, name, description: description || null, token_type: tokenType, ttl_days: ttlDays }),
      });
      if (!res.ok) throw new Error(await res.text());
      const created = (await res.json().catch(() => null)) as HoneytokenRecord | null;
      onCreate(created);
      onClose();
    } catch (e: unknown) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  };

  const info = TOKEN_TYPES[tokenType];

  return (
    <div className="fixed inset-0 bg-black/40 flex items-center justify-center z-50">
      <div className="bg-gray-900 rounded-lg shadow-xl border border-gray-700 w-full max-w-md p-6">
        <h2 className="text-lg font-semibold text-gray-100 mb-4">Create Honeytoken</h2>
        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-400 mb-1">Name *</label>
            <input
              className="w-full border border-gray-600 bg-gray-800 text-gray-200 rounded-md px-3 py-2 text-sm focus:ring-2 focus:ring-blue-500 outline-none"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="e.g. Finance share passwords note"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-400 mb-1">Description</label>
            <textarea
              className="w-full border border-gray-600 bg-gray-800 text-gray-200 rounded-md px-3 py-2 text-sm focus:ring-2 focus:ring-blue-500 outline-none"
              rows={2}
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="Where you plan to plant it"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-400 mb-1">Type *</label>
            <select
              aria-label="Token type"
              className="w-full border border-gray-600 bg-gray-800 text-gray-200 rounded-md px-3 py-2 text-sm focus:ring-2 focus:ring-blue-500 outline-none"
              value={tokenType}
              onChange={(e) => setTokenType(e.target.value)}
            >
              {TOKEN_TYPE_ORDER.map((t) => (
                <option key={t} value={t}>
                  {TOKEN_TYPES[t].label}
                </option>
              ))}
            </select>
            <p data-testid="type-help" className={`mt-2 text-xs ${info.alerts ? "text-green-300" : "text-yellow-300"}`}>
              {info.alerts ? "Alerts when opened. " : "Decoy only: it will not alert. "}
              {info.plant}
            </p>
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-400 mb-1">TTL (days)</label>
            <input
              type="number"
              className="w-full border border-gray-600 bg-gray-800 text-gray-200 rounded-md px-3 py-2 text-sm focus:ring-2 focus:ring-blue-500 outline-none"
              value={ttlDays}
              onChange={(e) => setTtlDays(Number(e.target.value))}
              min={1}
            />
          </div>
          {error && <p className="text-sm text-red-400">{error}</p>}
        </div>
        <div className="flex justify-end gap-3 mt-6">
          <button onClick={onClose} className="px-4 py-2 text-sm text-gray-400 hover:text-gray-200">
            Cancel
          </button>
          <button onClick={submit} disabled={loading || !name} className="px-4 py-2 text-sm bg-blue-600 text-white rounded-md hover:bg-blue-700 disabled:opacity-50">
            {loading ? "Creating…" : "Create"}
          </button>
        </div>
      </div>
    </div>
  );
}

function CopyButton({ value }: { value: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      type="button"
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(value);
          setCopied(true);
          setTimeout(() => setCopied(false), 1500);
        } catch {
          /* the value is selectable on screen */
        }
      }}
      className="text-xs px-2 py-1 rounded border border-gray-700 text-gray-300 hover:bg-gray-800 shrink-0"
    >
      {copied ? "Copied" : "Copy"}
    </button>
  );
}

function TokenDetails({ token, onClose }: { token: HoneytokenRecord; onClose: () => void }) {
  const { data: triggers, isLoading } = useSWR<Trigger[]>(`${API}/api/v1/honeytokens/${token.id}/triggers`, fetcher, { refreshInterval: 10_000 });
  const info = TOKEN_TYPES[token.token_type];
  const alerts = canAlert(token);
  const link = plantables(token).find(([k]) => k === "url" || k === "beacon_url")?.[1];

  return (
    <div className="fixed inset-0 bg-black/40 flex items-center justify-center z-50">
      <div className="bg-gray-900 rounded-lg shadow-xl border border-gray-700 w-full max-w-2xl p-6 max-h-[85vh] flex flex-col">
        <div className="flex justify-between items-center mb-3">
          <h2 className="text-lg font-semibold text-gray-100">{token.name}</h2>
          <button onClick={onClose} aria-label="Close" className="text-gray-500 hover:text-gray-300 text-lg">
            ✕
          </button>
        </div>
        <div className="overflow-y-auto flex-1 space-y-4">
          <p className={`text-sm ${alerts ? "text-green-300" : "text-yellow-300"}`} data-testid="detection">
            {alerts ? "This token alerts when its link is opened." : "This token is a decoy only: nothing watches for it being used yet."}
          </p>
          {info && <p className="text-sm text-gray-400">{info.plant}</p>}

          <div>
            <p className="text-xs font-medium text-gray-400 mb-1">Plant this</p>
            <ul className="space-y-2">
              {plantables(token).map(([key, value]) => (
                <li key={key} className="flex items-start gap-2">
                  <span className="w-28 shrink-0 text-xs text-gray-500">{key}</span>
                  <span className="flex-1 text-sm font-mono text-gray-200 break-all select-all">{value}</span>
                  <CopyButton value={value} />
                </li>
              ))}
            </ul>
          </div>

          {link && token.status === "active" && (
            <p className="text-xs text-gray-500">
              To test it,{" "}
              <a href={link} target="_blank" rel="noopener noreferrer" className="text-blue-400 hover:text-blue-300">
                open the link
              </a>
              . That counts as a real trigger and marks the token triggered, so test with a spare token and plant a fresh one. The link only works from a machine that can reach it: it points at{" "}
              <span className="font-mono">{new URL(link).origin}</span>.
            </p>
          )}

          <div>
            <p className="text-xs font-medium text-gray-400 mb-1">Trigger history</p>
            {isLoading ? (
              <p className="text-sm text-gray-500">Loading…</p>
            ) : !triggers?.length ? (
              <p className="text-sm text-gray-500">No triggers yet: nobody has opened it.</p>
            ) : (
              <table className="w-full text-sm">
                <thead className="bg-gray-800">
                  <tr>
                    <th className="px-3 py-2 text-left font-medium text-gray-400">Triggered</th>
                    <th className="px-3 py-2 text-left font-medium text-gray-400">Source IP</th>
                    <th className="px-3 py-2 text-left font-medium text-gray-400">Browser</th>
                    <th className="px-3 py-2 text-left font-medium text-gray-400">Alert sent</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-800">
                  {triggers.map((t) => (
                    <tr key={t.id} className="hover:bg-gray-800/50">
                      <td className="px-3 py-2 text-gray-300" suppressHydrationWarning>
                        {new Date(t.triggered_at).toLocaleString()}
                      </td>
                      <td className="px-3 py-2 text-gray-400">{t.source_ip ?? "—"}</td>
                      <td className="px-3 py-2 text-gray-500 max-w-[14rem] truncate" title={t.user_agent ?? ""}>
                        {t.user_agent ?? "—"}
                      </td>
                      <td className="px-3 py-2">
                        <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium ${t.alert_sent ? "bg-green-900/40 text-green-300" : "bg-gray-800 text-gray-400"}`}>
                          {t.alert_sent ? "Yes" : "No"}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

export default function HoneytokensPage() {
  const [statusFilter, setStatusFilter] = useState<string>("");
  const [typeFilter, setTypeFilter] = useState<string>("");
  const [showCreate, setShowCreate] = useState(false);
  const [selectedId, setSelectedId] = useState<string | null>(null);

  const listKey = `${API}/api/v1/honeytokens?tenant_id=${TENANT_ID}${statusFilter ? `&status=${statusFilter}` : ""}${typeFilter ? `&token_type=${typeFilter}` : ""}`;

  const { data: rawTokens, isLoading } = useSWR<HoneytokenRecord[]>(listKey, fetcher, { refreshInterval: 15_000 });
  const tokens = Array.isArray(rawTokens) ? rawTokens : undefined;
  const selected = tokens?.find((t) => t.id === selectedId) ?? null;

  const refresh = () => mutate(listKey);

  const revoke = async (id: string) => {
    await authFetch(`${API}/api/v1/honeytokens/${id}/revoke`, { method: "PATCH" });
    refresh();
  };

  const remove = async (id: string) => {
    if (!confirm("Delete this honeytoken?")) return;
    await authFetch(`${API}/api/v1/honeytokens/${id}`, { method: "DELETE" });
    refresh();
  };

  const counts = {
    total: tokens?.length ?? 0,
    active: tokens?.filter((t) => t.status === "active").length ?? 0,
    triggered: tokens?.filter((t) => t.status === "triggered").length ?? 0,
    revoked: tokens?.filter((t) => t.status === "revoked").length ?? 0,
  };

  return (
    <div className="p-6 max-w-6xl mx-auto">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold text-gray-100">Honeytokens</h1>
          <p className="text-sm text-gray-500 mt-1">
            Plant a decoy link or document where only an intruder would look; opening it raises an alert. The other types are decoy values only for now: nothing watches for their use.
          </p>
        </div>
        <button onClick={() => setShowCreate(true)} className="px-4 py-2 bg-blue-600 text-white text-sm font-medium rounded-lg hover:bg-blue-700">
          + New Token
        </button>
      </div>

      <div className="grid grid-cols-4 gap-4 mb-6">
        {[
          { label: "Total", value: counts.total, color: "text-gray-100" },
          { label: "Active", value: counts.active, color: "text-green-400" },
          { label: "Triggered", value: counts.triggered, color: "text-red-400" },
          { label: "Revoked", value: counts.revoked, color: "text-yellow-400" },
        ].map((s) => (
          <div key={s.label} className="bg-gray-900/60 border border-gray-700 rounded-lg p-4">
            <p className="text-xs text-gray-500 uppercase tracking-wide">{s.label}</p>
            <p className={`text-2xl font-bold mt-1 ${s.color}`}>{s.value}</p>
          </div>
        ))}
      </div>

      <div className="flex gap-3 mb-4">
        <select
          className="border border-gray-600 bg-gray-800 text-gray-200 rounded-md px-3 py-1.5 text-sm focus:ring-2 focus:ring-blue-500 outline-none"
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value)}
        >
          <option value="">All statuses</option>
          <option value="active">Active</option>
          <option value="triggered">Triggered</option>
          <option value="expired">Expired</option>
          <option value="revoked">Revoked</option>
        </select>
        <select
          className="border border-gray-600 bg-gray-800 text-gray-200 rounded-md px-3 py-1.5 text-sm focus:ring-2 focus:ring-blue-500 outline-none"
          value={typeFilter}
          onChange={(e) => setTypeFilter(e.target.value)}
        >
          <option value="">All types</option>
          {TOKEN_TYPE_ORDER.map((t) => (
            <option key={t} value={t}>
              {TOKEN_TYPES[t].label}
            </option>
          ))}
        </select>
      </div>

      <div className="bg-gray-900/60 border border-gray-700 rounded-lg overflow-hidden">
        {isLoading ? (
          <div className="p-8 text-center text-sm text-gray-500">Loading tokens…</div>
        ) : !tokens?.length ? (
          <div className="p-8 text-center text-sm text-gray-500">No honeytokens found. Create your first one.</div>
        ) : (
          <table className="w-full text-sm">
            <thead className="bg-gray-800 border-b border-gray-700">
              <tr>
                <th className="px-4 py-3 text-left font-medium text-gray-400">Name</th>
                <th className="px-4 py-3 text-left font-medium text-gray-400">Type</th>
                <th className="px-4 py-3 text-left font-medium text-gray-400">Detects</th>
                <th className="px-4 py-3 text-left font-medium text-gray-400">Status</th>
                <th className="px-4 py-3 text-left font-medium text-gray-400">Expires</th>
                <th className="px-4 py-3 text-left font-medium text-gray-400">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800">
              {tokens.map((token) => (
                <TokenRow key={token.id} token={token} onRevoke={revoke} onDelete={remove} onSelect={(id) => setSelectedId(id)} />
              ))}
            </tbody>
          </table>
        )}
      </div>

      {showCreate && (
        <CreateTokenModal
          onClose={() => setShowCreate(false)}
          onCreate={(created) => {
            refresh();
            if (created?.id) setSelectedId(created.id); // straight to what to plant
          }}
        />
      )}
      {selected && <TokenDetails token={selected} onClose={() => setSelectedId(null)} />}
    </div>
  );
}
