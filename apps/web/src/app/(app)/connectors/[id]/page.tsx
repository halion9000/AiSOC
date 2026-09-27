'use client';

import { useParams, useRouter } from 'next/navigation';
import { useEffect, useState } from 'react';
import { connectorsApi, type Connector } from '@/lib/api';
import { ArrowLeft, CheckCircle, XCircle, Loader2 } from 'lucide-react';

export default function ConnectorDetailPage() {
  const params = useParams();
  const router = useRouter();
  const connectorId = params.id as string;
  const [connector, setConnector] = useState<Connector | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    async function loadConnector() {
      try {
        setLoading(true);
        const data = await connectorsApi.list();
        const found = data.connectors.find((c) => c.id === connectorId);
        setConnector(found || null);
        if (!found) {
          setError(`Connector "${connectorId}" not found`);
        }
      } catch (err) {
        setError('Failed to load connector details');
      } finally {
        setLoading(false);
      }
    }
    loadConnector();
  }, [connectorId]);

  const handleToggle = async () => {
    if (!connector) return;
    const next = !connector.enabled;
    try {
      await connectorsApi.update(connector.id, { is_enabled: next });
      setConnector({ ...connector, enabled: next });
    } catch {
      alert('Failed to update connector');
    }
  };

  if (loading) {
    return (
      <div className="flex h-full items-center justify-center">
        <Loader2 className="h-8 w-8 animate-spin text-blue-500" />
        <span className="ml-3 text-gray-400">Loading connector...</span>
      </div>
    );
  }

  if (error || !connector) {
    return (
      <div className="mx-auto max-w-2xl px-6 py-12">
        <button
          onClick={() => router.back()}
          className="mb-6 inline-flex items-center gap-1.5 text-sm text-blue-400 hover:text-blue-300"
        >
          <ArrowLeft className="h-3.5 w-3.5" />
          Back
        </button>
        <div className="rounded-lg border border-red-500/20 bg-red-500/10 p-6 text-center">
          <XCircle className="mx-auto mb-3 h-10 w-10 text-red-400" />
          <p className="text-lg font-semibold text-white">{error || 'Connector not found'}</p>
          <button
            onClick={() => router.push('/connectors')}
            className="mt-4 rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-500"
          >
            View All Connectors
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="mx-auto max-w-3xl px-6 py-12">
      <button
        onClick={() => router.back()}
        className="mb-6 inline-flex items-center gap-1.5 text-sm text-blue-400 hover:text-blue-300"
      >
        <ArrowLeft className="h-3.5 w-3.5" />
        Back to Connectors
      </button>

      <div className="rounded-xl border border-white/10 bg-white/5 p-8">
        <div className="mb-6 flex items-start justify-between">
          <div>
            <h1 className="text-2xl font-bold text-white">{connector.name}</h1>
            {connector.description && (
              <p className="mt-2 text-gray-400">{connector.description}</p>
            )}
          </div>
          <div
            className={`rounded-full px-3 py-1 text-xs font-medium ${
              connector.enabled ? 'bg-green-500/20 text-green-400' : 'bg-gray-500/20 text-gray-400'
            }`}
          >
            {connector.enabled ? 'Active' : 'Inactive'}
          </div>
        </div>

        <div className="space-y-4 rounded-lg bg-black/20 p-4">
          <div className="flex items-center justify-between">
            <span className="text-sm text-gray-400">Status</span>
            <div className="flex items-center gap-2">
              {connector.enabled ? (
                <CheckCircle className="h-4 w-4 text-green-400" />
              ) : (
                <XCircle className="h-4 w-4 text-gray-500" />
              )}
              <span className={connector.enabled ? 'text-green-400' : 'text-gray-500'}>
                {connector.enabled ? 'Enabled' : 'Disabled'}
              </span>
            </div>
          </div>

          {connector.status && (
            <div className="flex items-center justify-between">
              <span className="text-sm text-gray-400">Connection</span>
              <span className="text-sm capitalize text-gray-300">{connector.status}</span>
            </div>
          )}

          {connector.lastSync && (
            <div className="flex items-center justify-between">
              <span className="text-sm text-gray-400">Last Sync</span>
              <span className="text-sm text-gray-300">
                {new Date(connector.lastSync).toLocaleString()}
              </span>
            </div>
          )}
        </div>

        <div className="mt-6 flex gap-3">
          <button
            onClick={handleToggle}
            className={`rounded-lg px-4 py-2 text-sm font-medium transition-colors ${
              connector.enabled
                ? 'bg-red-600 hover:bg-red-500'
                : 'bg-green-600 hover:bg-green-500'
            } text-white`}
          >
            {connector.enabled ? 'Disable Connector' : 'Enable Connector'}
          </button>
          <button
            onClick={() => router.push('/connectors')}
            className="rounded-lg border border-white/10 bg-white/5 px-4 py-2 text-sm font-medium text-gray-300 transition-colors hover:bg-white/10"
          >
            Cancel
          </button>
        </div>
      </div>
    </div>
  );
}