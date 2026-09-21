'use client';

import { useState } from 'react';
import useSWR from 'swr';
import { clsx } from 'clsx';
import { EmptyState, EmptyStateIcons } from '@/components/ui/EmptyState';

const fetcher = async (url: string) => {
  const r = await fetch(url, { credentials: 'include' });
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  const text = await r.text();
  try { return JSON.parse(text); } catch { throw new Error('Invalid JSON'); }
};

type RiskLevel = 'critical' | 'high' | 'medium' | 'low' | 'info';
type AssetType = 'domain' | 'ip' | 'cert' | 'subdomain' | 'service';

interface Asset {
  id: string;
  asset: string;
  type: AssetType;
  status: 'healthy' | 'warning' | 'critical';
  risk: RiskLevel;
  lastSeen: string;
}

interface Certificate {
  id: string;
  domain: string;
  issuer: string;
  expiryDate: string;
  daysRemaining: number;
  status: 'valid' | 'expiring' | 'expired';
}

const RISK_CONFIG: Record<RiskLevel, { label: string; className: string }> = {
  critical: { label: 'Critical', className: 'text-red-400 bg-red-500/10 border-red-500/20' },
  high: { label: 'High', className: 'text-orange-400 bg-orange-500/10 border-orange-500/20' },
  medium: { label: 'Medium', className: 'text-yellow-400 bg-yellow-500/10 border-yellow-500/20' },
  low: { label: 'Low', className: 'text-blue-400 bg-blue-500/10 border-blue-500/20' },
  info: { label: 'Info', className: 'text-gray-400 bg-gray-500/10 border-gray-500/20' },
};

const STATUS_COLOR: Record<Asset['status'], string> = {
  healthy: 'text-green-400 bg-green-500/10 border-green-500/20',
  warning: 'text-amber-400 bg-amber-500/10 border-amber-500/20',
  critical: 'text-red-400 bg-red-500/10 border-red-500/20',
};

const CERT_STATUS_COLOR: Record<Certificate['status'], string> = {
  valid: 'text-green-400 bg-green-500/10 border-green-500/20',
  expiring: 'text-amber-400 bg-amber-500/10 border-amber-500/20',
  expired: 'text-red-400 bg-red-500/10 border-red-500/20',
};

const TYPE_LABELS: Record<AssetType, string> = {
  domain: 'Domain',
  ip: 'IP Address',
  cert: 'Certificate',
  subdomain: 'Subdomain',
  service: 'Service',
};

export function EASMView() {
  const [assetFilter, setAssetFilter] = useState<Asset['status'] | 'all'>('all');
  const { data: assets, isLoading: assetsLoading } = useSWR<Asset[]>('/api/v1/easm/assets', fetcher);
  const { data: certificates, isLoading: certsLoading } = useSWR<Certificate[]>('/api/v1/easm/certificates', fetcher);

  const allAssets = assets ?? [];
  const filteredAssets = assetFilter === 'all'
    ? allAssets
    : allAssets.filter((a) => a.status === assetFilter);

  const summary = {
    totalAssets: allAssets.length,
    exposedServices: allAssets.filter((a) => a.status === 'critical' || a.status === 'warning').length,
    certIssues: (certificates ?? []).filter((c) => c.status !== 'valid').length,
    riskScore: 0, // TODO: compute from real data when backend exposes it
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-xl font-semibold text-gray-100">External Attack Surface Management</h1>
        <p className="text-sm text-gray-500 mt-0.5">Monitor external assets, exposed services, and certificate health</p>
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-4 gap-3">
        {[
          { label: 'Total Assets', value: summary.totalAssets, color: 'text-blue-400' },
          { label: 'Exposed Services', value: summary.exposedServices, color: 'text-amber-400' },
          { label: 'Certificate Issues', value: summary.certIssues, color: 'text-red-400' },
          { label: 'Risk Score', value: `${summary.riskScore}/100`, color: summary.riskScore >= 70 ? 'text-amber-400' : 'text-green-400' },
        ].map((card) => (
          <div key={card.label} className="bg-gray-900/60 border border-gray-800/60 rounded-xl p-4">
            <p className={clsx('text-2xl font-bold', card.color)}>{card.value}</p>
            <p className="text-xs text-gray-500 mt-0.5">{card.label}</p>
          </div>
        ))}
      </div>

      {/* Asset Discovery Table */}
      <div className="bg-gray-900/60 border border-gray-800/60 rounded-xl overflow-hidden">
        <div className="px-5 py-4 border-b border-gray-800/60 flex items-center justify-between">
          <div>
            <h2 className="text-sm font-semibold text-gray-200">Asset Discovery</h2>
            <p className="text-xs text-gray-500 mt-0.5">{filteredAssets.length} assets found</p>
          </div>
          <div className="flex gap-2">
            {(['all', 'healthy', 'warning', 'critical'] as const).map((f) => (
              <button
                key={f}
                onClick={() => setAssetFilter(f)}
                className={clsx(
                  'text-xs px-3 py-1 rounded-lg border transition-colors',
                  assetFilter === f
                    ? 'bg-blue-600/15 text-blue-300 border-blue-600/30'
                    : 'text-gray-400 border-gray-800 hover:border-gray-700'
                )}
              >
                {f === 'all' ? 'All' : f.charAt(0).toUpperCase() + f.slice(1)}
              </button>
            ))}
          </div>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-800/40">
                <th className="text-left text-xs font-medium text-gray-500 px-5 py-3">Asset</th>
                <th className="text-left text-xs font-medium text-gray-500 px-5 py-3">Type</th>
                <th className="text-left text-xs font-medium text-gray-500 px-5 py-3">Status</th>
                <th className="text-left text-xs font-medium text-gray-500 px-5 py-3">Risk</th>
                <th className="text-left text-xs font-medium text-gray-500 px-5 py-3">Last Seen</th>
              </tr>
            </thead>
            <tbody>
              {filteredAssets.length === 0 ? (
                <tr>
                  <td colSpan={5} className="py-0">
                    <EmptyState
                      icon={EmptyStateIcons.shield}
                      title="No assets match this filter"
                      description="Try selecting a different status filter or view all assets."
                      action={
                        <button
                          type="button"
                          onClick={() => setAssetFilter('all')}
                          className="rounded-lg bg-gray-800 px-4 py-2 text-sm text-gray-200 hover:bg-gray-700 transition-colors"
                        >
                          Show all assets
                        </button>
                      }
                    />
                  </td>
                </tr>
              ) : (
                filteredAssets.map((asset) => (
                  <tr key={asset.id} className="border-b border-gray-800/30 hover:bg-gray-800/30 transition-colors">
                    <td className="px-5 py-3">
                      <span className="text-gray-200 font-mono text-xs">{asset.asset}</span>
                    </td>
                    <td className="px-5 py-3 text-gray-400 text-xs">{TYPE_LABELS[asset.type]}</td>
                    <td className="px-5 py-3">
                      <span className={clsx('text-xs font-medium px-2 py-0.5 rounded border', STATUS_COLOR[asset.status])}>
                        {asset.status.charAt(0).toUpperCase() + asset.status.slice(1)}
                      </span>
                    </td>
                    <td className="px-5 py-3">
                      <span className={clsx('text-xs font-medium px-2 py-0.5 rounded border', RISK_CONFIG[asset.risk].className)}>
                        {RISK_CONFIG[asset.risk].label}
                      </span>
                    </td>
                    <td className="px-5 py-3 text-xs text-gray-500">{asset.lastSeen}</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Certificate Monitor */}
      <div className="bg-gray-900/60 border border-gray-800/60 rounded-xl overflow-hidden">
        <div className="px-5 py-4 border-b border-gray-800/60">
          <h2 className="text-sm font-semibold text-gray-200">Certificate Monitor</h2>
          <p className="text-xs text-gray-500 mt-0.5">Track TLS certificate health and expiry dates</p>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-800/40">
                <th className="text-left text-xs font-medium text-gray-500 px-5 py-3">Domain</th>
                <th className="text-left text-xs font-medium text-gray-500 px-5 py-3">Issuer</th>
                <th className="text-left text-xs font-medium text-gray-500 px-5 py-3">Expiry Date</th>
                <th className="text-left text-xs font-medium text-gray-500 px-5 py-3">Days Remaining</th>
                <th className="text-left text-xs font-medium text-gray-500 px-5 py-3">Status</th>
              </tr>
            </thead>
            <tbody>
              {(certificates ?? []).map((cert) => (
                <tr key={cert.id} className="border-b border-gray-800/30 hover:bg-gray-800/30 transition-colors">
                  <td className="px-5 py-3">
                    <span className="text-gray-200 font-mono text-xs">{cert.domain}</span>
                  </td>
                  <td className="px-5 py-3 text-gray-400 text-xs">{cert.issuer}</td>
                  <td className="px-5 py-3 text-gray-400 text-xs">{cert.expiryDate}</td>
                  <td className="px-5 py-3">
                    <span className={clsx(
                      'text-xs font-medium',
                      cert.daysRemaining <= 0 ? 'text-red-400' :
                      cert.daysRemaining <= 30 ? 'text-amber-400' :
                      'text-green-400'
                    )}>
                      {cert.daysRemaining <= 0 ? `${Math.abs(cert.daysRemaining)}d overdue` : `${cert.daysRemaining}d`}
                    </span>
                  </td>
                  <td className="px-5 py-3">
                    <span className={clsx('text-xs font-medium px-2 py-0.5 rounded border', CERT_STATUS_COLOR[cert.status])}>
                      {cert.status.charAt(0).toUpperCase() + cert.status.slice(1)}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
