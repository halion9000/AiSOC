'use client';

/**
 * EditConnectorModal — inline edit dialog for existing connector instances.
 *
 * Mirrors the config-form step of AddConnectorModal but pre-populates fields
 * from the saved connector's `connector_config` and `auth_config`. Secrets
 * are never sent back to the client by the API, so secret fields always start
 * empty with a "leave blank to keep current value" hint.
 *
 * Submits via `connectorsApi.update()` (PATCH) which only sends changed
 * fields — the backend merges them onto the existing row.
 */

import { useEffect, useMemo, useState } from 'react';
import { clsx } from 'clsx';
import toast from 'react-hot-toast';
import {
  connectorsApi,
  type Connector,
  type ConnectorCatalogEntry,
  type ConnectorSchemaField,
} from '@/lib/api';

// ─── Field rendering (same as AddConnectorModal) ─────────────────────────────

function FieldInput({
  field,
  value,
  onChange,
}: {
  field: ConnectorSchemaField;
  value: string | number | boolean;
  onChange: (next: string | number | boolean) => void;
}) {
  const baseClass =
    'w-full bg-gray-950/60 border border-gray-800 rounded-lg px-3 py-2 text-sm text-gray-100 placeholder-gray-600 focus:outline-none focus:border-blue-500/60 focus:ring-1 focus:ring-blue-500/30 transition-colors';

  switch (field.type) {
    case 'secret':
      return (
        <input
          type="password"
          autoComplete="new-password"
          value={String(value ?? '')}
          onChange={(e) => onChange(e.target.value)}
          placeholder="Leave blank to keep current value"
          className={clsx(baseClass, 'font-mono')}
        />
      );
    case 'textarea':
      return (
        <textarea
          value={String(value ?? '')}
          onChange={(e) => onChange(e.target.value)}
          placeholder={field.placeholder}
          rows={4}
          className={clsx(baseClass, 'font-mono text-xs resize-y min-h-[80px]')}
        />
      );
    case 'select':
      return (
        <select
          value={String(value ?? '')}
          onChange={(e) => onChange(e.target.value)}
          className={baseClass}
        >
          {!field.required && <option value="">— none —</option>}
          {(field.options ?? []).map((opt) => (
            <option key={opt.value} value={opt.value}>
              {opt.label}
            </option>
          ))}
        </select>
      );
    case 'boolean':
      return (
        <label className="flex items-center gap-2 cursor-pointer select-none">
          <input
            type="checkbox"
            checked={Boolean(value)}
            onChange={(e) => onChange(e.target.checked)}
            className="h-4 w-4 rounded border-gray-700 bg-gray-900 text-blue-500 focus:ring-blue-500/30"
          />
          <span className="text-sm text-gray-300">{field.placeholder ?? 'Enabled'}</span>
        </label>
      );
    case 'number':
      return (
        <input
          type="number"
          value={typeof value === 'number' ? value : Number(value ?? 0)}
          onChange={(e) => {
            const parsed = e.target.value === '' ? 0 : Number(e.target.value);
            onChange(Number.isNaN(parsed) ? 0 : parsed);
          }}
          placeholder={field.placeholder}
          className={baseClass}
        />
      );
    case 'string':
    default:
      return (
        <input
          type="text"
          value={String(value ?? '')}
          onChange={(e) => onChange(e.target.value)}
          placeholder={field.placeholder}
          className={baseClass}
        />
      );
  }
}

// ─── Modal ───────────────────────────────────────────────────────────────────

interface EditConnectorModalProps {
  open: boolean;
  connector: Connector | null;
  catalogEntry: ConnectorCatalogEntry | undefined;
  onClose: () => void;
  onUpdated: () => void;
}

export function EditConnectorModal({
  open,
  connector,
  catalogEntry,
  onClose,
  onUpdated,
}: EditConnectorModalProps) {
  const [saving, setSaving] = useState(false);
  const [name, setName] = useState('');
  const [values, setValues] = useState<Record<string, string | number | boolean>>({});
  const [tags, setTags] = useState('');

  // Pre-populate when the modal opens with a new connector
  useEffect(() => {
    if (!open || !connector) return;
    setName(connector.name ?? '');
    setTags((connector.tags ?? []).join(', '));

    const initial: Record<string, string | number | boolean> = {};
    const fields = catalogEntry?.fields ?? [];
    for (const f of fields) {
      if (f.type === 'secret') {
        // Secrets are never returned by the API — always start empty
        initial[f.name] = '';
        continue;
      }
      const configVal =
        (connector.connectorConfig as Record<string, unknown>)?.[f.name] ??
        (connector.authConfig as Record<string, unknown>)?.[f.name];
      if (configVal !== undefined && configVal !== null) {
        initial[f.name] = configVal as string | number | boolean;
      } else if (f.default !== undefined && f.default !== null) {
        initial[f.name] = f.default as string | number | boolean;
      } else {
        initial[f.name] = f.type === 'boolean' ? false : f.type === 'number' ? 0 : '';
      }
    }
    setValues(initial);
  }, [open, connector, catalogEntry]);

  const fields = useMemo(() => catalogEntry?.fields ?? [], [catalogEntry]);

  const handleChange = (fieldName: string, next: string | number | boolean) => {
    setValues((prev) => ({ ...prev, [fieldName]: next }));
  };

  const handleSave = async () => {
    if (!connector) return;
    setSaving(true);
    try {
      // Build the PATCH payload — only include non-empty values so the
      // backend preserves unchanged fields (especially secrets).
      const authConfig: Record<string, unknown> = {};
      const connectorConfig: Record<string, unknown> = {};
      for (const f of fields) {
        const v = values[f.name];
        const isEmpty = v === '' || v === null || v === undefined;
        if (isEmpty) continue; // omit → backend keeps existing value
        if (f.type === 'secret') {
          authConfig[f.name] = v;
        } else {
          connectorConfig[f.name] = v;
        }
      }

      const parsedTags = tags
        .split(',')
        .map((t) => t.trim())
        .filter(Boolean);

      await connectorsApi.update(connector.id, {
        name: name.trim() || undefined,
        auth_config: Object.keys(authConfig).length > 0 ? authConfig : undefined,
        connector_config: Object.keys(connectorConfig).length > 0 ? connectorConfig : undefined,
        tags: parsedTags.length > 0 ? parsedTags : undefined,
      });

      toast.success(`Updated ${name || connector.name}`);
      onUpdated();
      onClose();
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Failed to update connector';
      toast.error(msg);
    } finally {
      setSaving(false);
    }
  };

  if (!open || !connector) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
      <div className="bg-gray-900 border border-gray-800 rounded-xl shadow-2xl w-full max-w-lg max-h-[85vh] overflow-y-auto">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-gray-800">
          <div>
            <h2 className="text-lg font-semibold text-gray-100">Edit Connector</h2>
            <p className="text-xs text-gray-500 mt-0.5">
              {catalogEntry?.connector_name ?? connector.type} — {connector.name}
            </p>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="text-gray-500 hover:text-gray-300 transition-colors"
          >
            <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        {/* Form */}
        <div className="px-6 py-4 space-y-4">
          {/* Name */}
          <div>
            <label className="block text-xs font-medium text-gray-400 mb-1.5">Display Name</label>
            <input
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              className="w-full bg-gray-950/60 border border-gray-800 rounded-lg px-3 py-2 text-sm text-gray-100 placeholder-gray-600 focus:outline-none focus:border-blue-500/60 focus:ring-1 focus:ring-blue-500/30 transition-colors"
              placeholder="My Connector"
            />
          </div>

          {/* Dynamic fields from catalog schema */}
          {fields.map((field) => (
            <div key={field.name}>
              <label className="block text-xs font-medium text-gray-400 mb-1.5">
                {field.label ?? field.name}
                {field.required && <span className="text-red-400 ml-1">*</span>}
              </label>
              <FieldInput
                field={field}
                value={values[field.name] ?? ''}
                onChange={(v) => handleChange(field.name, v)}
              />
              {field.help_text && (
                <p className="text-[11px] text-gray-600 mt-1">{field.help_text}</p>
              )}
            </div>
          ))}

          {/* Tags */}
          <div>
            <label className="block text-xs font-medium text-gray-400 mb-1.5">Tags</label>
            <input
              type="text"
              value={tags}
              onChange={(e) => setTags(e.target.value)}
              className="w-full bg-gray-950/60 border border-gray-800 rounded-lg px-3 py-2 text-sm text-gray-100 placeholder-gray-600 focus:outline-none focus:border-blue-500/60 focus:ring-1 focus:ring-blue-500/30 transition-colors"
              placeholder="prod, critical, us-east-1"
            />
            <p className="text-[11px] text-gray-600 mt-1">Comma-separated labels for filtering.</p>
          </div>
        </div>

        {/* Footer */}
        <div className="flex items-center justify-end gap-3 px-6 py-4 border-t border-gray-800">
          <button
            type="button"
            onClick={onClose}
            disabled={saving}
            className="px-4 py-2 text-sm text-gray-400 hover:text-gray-200 transition-colors disabled:opacity-50"
          >
            Cancel
          </button>
          <button
            type="button"
            onClick={handleSave}
            disabled={saving}
            className="bg-blue-600 hover:bg-blue-500 text-white text-sm font-medium px-5 py-2 rounded-lg transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {saving ? 'Saving…' : 'Save Changes'}
          </button>
        </div>
      </div>
    </div>
  );
}