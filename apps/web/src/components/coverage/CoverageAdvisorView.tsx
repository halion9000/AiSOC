'use client';

import { useState } from 'react';
import Link from 'next/link';
import useSWR from 'swr';
import { clsx } from 'clsx';
import { EmptyState, EmptyStateIcons } from '@/components/ui/EmptyState';
import { ErrorState } from '@/components/ui/ErrorState';
import { detectionApi, type DetectionCoverageCell } from '@/lib/api';

export type CoverageStatus = 'covered' | 'partial' | 'gap';

interface ReferenceTechnique {
  id: string;
  name: string;
  tactic: string;
  /** What to build when this technique is not covered. */
  advice: string;
}

/**
 * Techniques a SOC is generally expected to cover, with advice for when it does not. This is a REFERENCE list, not data about this workspace.
 *
 * This page used to hard-code a coverage STATUS for each of these ("covered" / "partial" / "gap"), a priority, and recommendations such as "Ransomware canary files active" and "Rate-limit rules
 * deployed across tenants", and derived its summary cards from them, so it reported a coverage assessment that nothing had computed and made claims about deployed rules that were not true. Its
 * "Generate Detection" button also toasted "Detection rule draft created" and created nothing. Statuses now come from the workspace's real rules (see assessTechnique) and the button links to
 * the rule editor.
 */
export const REFERENCE_TECHNIQUES: ReferenceTechnique[] = [
  { id: 'T1059', name: 'Command and Scripting Interpreter', tactic: 'Execution', advice: 'Detect suspicious interpreter launches (PowerShell, bash, cmd, wscript) with unusual parents or arguments' },
  { id: 'T1059.001', name: 'PowerShell', tactic: 'Execution', advice: 'Enable ScriptBlock logging and alert on encoded commands and download cradles' },
  { id: 'T1071', name: 'Application Layer Protocol', tactic: 'Command & Control', advice: 'Add DNS-over-HTTPS detection rule' },
  { id: 'T1053', name: 'Scheduled Task/Job', tactic: 'Persistence', advice: 'Deploy schtasks / cron anomaly detection' },
  { id: 'T1078', name: 'Valid Accounts', tactic: 'Initial Access', advice: 'Correlate impossible-travel with auth logs' },
  { id: 'T1021', name: 'Remote Services', tactic: 'Lateral Movement', advice: 'Monitor RDP/SSH lateral pivots' },
  { id: 'T1486', name: 'Data Encrypted for Impact', tactic: 'Impact', advice: 'Alert on mass file renames, high-entropy writes and shadow-copy deletion' },
  { id: 'T1027', name: 'Obfuscated Files or Information', tactic: 'Defense Evasion', advice: 'Add entropy-based payload analysis' },
  { id: 'T1562', name: 'Impair Defenses', tactic: 'Defense Evasion', advice: 'Detect tamper of EDR services' },
  { id: 'T1110', name: 'Brute Force', tactic: 'Credential Access', advice: 'Alert on repeated authentication failures per account and source, followed by a success' },
  { id: 'T1048', name: 'Exfiltration Over Alternative Protocol', tactic: 'Exfiltration', advice: 'Monitor DNS/ICMP tunneling patterns' },
  { id: 'T1087', name: 'Account Discovery', tactic: 'Discovery', advice: 'Alert on bulk LDAP enumeration' },
  { id: 'T1547', name: 'Boot or Logon Autostart Execution', tactic: 'Persistence', advice: 'Registry run-key change monitoring' },
  { id: 'T1569', name: 'System Services', tactic: 'Execution', advice: 'Alert on new service creation and service binary path changes' },
  { id: 'T1190', name: 'Exploit Public-Facing Application', tactic: 'Initial Access', advice: 'WAF log correlation with CVE feeds' },
];

export interface TechniqueAssessment extends ReferenceTechnique {
  status: CoverageStatus;
  /** Active rules mapped to this technique or any of its sub-techniques. */
  activeRules: number;
  /** All rules (active or not) mapped to this technique or any of its sub-techniques. */
  totalRules: number;
}

/**
 * Assess one technique against the workspace's real coverage cells.
 *
 *  - covered: at least one ACTIVE rule is mapped to it (or to one of its sub-techniques, T1059 counts T1059.001)
 *  - partial: rules are mapped to it, but none is active (disabled or still in testing)
 *  - gap:     no rule is mapped to it at all
 */
export function assessTechnique(technique: ReferenceTechnique, cells: DetectionCoverageCell[]): TechniqueAssessment {
  const related = cells.filter((c) => c.techniqueId === technique.id || c.techniqueId.startsWith(`${technique.id}.`));
  const activeRules = related.reduce((sum, c) => sum + c.activeRules, 0);
  const totalRules = related.reduce((sum, c) => sum + c.totalRules, 0);
  const status: CoverageStatus = activeRules > 0 ? 'covered' : totalRules > 0 ? 'partial' : 'gap';
  return { ...technique, status, activeRules, totalRules };
}

const STATUS_STYLES: Record<CoverageStatus, { bg: string; text: string; label: string }> = {
  covered: { bg: 'bg-green-500/20', text: 'text-green-400', label: 'Covered' },
  partial: { bg: 'bg-amber-500/20', text: 'text-amber-400', label: 'Partial' },
  gap: { bg: 'bg-red-500/20', text: 'text-red-400', label: 'Gap' },
};

// Priority follows from the status: a technique with no rule at all is the most urgent, one whose rules are all inactive is next, a covered one is not.
const PRIORITY: Record<CoverageStatus, { label: string; bg: string; text: string }> = {
  gap: { label: 'High', bg: 'bg-red-500/20', text: 'text-red-400' },
  partial: { label: 'Medium', bg: 'bg-amber-500/20', text: 'text-amber-400' },
  covered: { label: 'Low', bg: 'bg-green-500/20', text: 'text-green-400' },
};

const plural = (n: number, word: string) => `${n} ${word}${n === 1 ? '' : 's'}`;

function recommendation(t: TechniqueAssessment): string {
  if (t.status === 'covered') return `Covered by ${plural(t.activeRules, 'active rule')}`;
  if (t.status === 'partial') return `${plural(t.totalRules, 'mapped rule')}, none active. Enable or tune one. ${t.advice}`;
  return t.advice;
}

export default function CoverageAdvisorView() {
  const { data, error, isLoading, mutate } = useSWR('detection.coverage', () => detectionApi.coverage(), { revalidateOnFocus: false, shouldRetryOnError: false });
  const [statusFilter, setStatusFilter] = useState<CoverageStatus | 'all'>('all');

  if (error && !data) {
    return (
      <div className="space-y-8 p-6 max-w-7xl mx-auto">
        <ErrorState title="Couldn't load detection coverage" description="The detection service didn't respond." error={error} onRetry={() => mutate()} />
      </div>
    );
  }
  if (!data) {
    return (
      <div className="space-y-8 p-6 max-w-7xl mx-auto">
        <p className="text-sm text-gray-400">{isLoading ? 'Loading detection coverage\u2026' : 'No coverage data.'}</p>
      </div>
    );
  }

  const techniques = REFERENCE_TECHNIQUES.map((t) => assessTechnique(t, data.cells));
  const filteredTechniques = statusFilter === 'all' ? techniques : techniques.filter((t) => t.status === statusFilter);

  const covered = techniques.filter((t) => t.status === 'covered').length;
  const gaps = techniques.filter((t) => t.status === 'gap').length;
  const coveragePct = Math.round((covered / techniques.length) * 100);

  const summaryCards = [
    { label: 'Techniques Covered', value: covered },
    { label: 'Coverage %', value: `${coveragePct}%` },
    { label: 'Critical Gaps', value: gaps },
    { label: 'Recommended Detections', value: techniques.filter((t) => t.status !== 'covered').length },
  ];

  return (
    <div className="space-y-8 p-6 max-w-7xl mx-auto">
      <div>
        <h1 className="text-2xl font-bold text-white">Coverage Gap Advisor</h1>
        <p className="text-gray-400 mt-1">Identify MITRE ATT&amp;CK coverage gaps and get actionable detection recommendations</p>
        <p className="text-xs text-gray-500 mt-2">
          Checked against {techniques.length} reference techniques, using the {data.summary.activeRules} active of {data.summary.totalRules} detection rules in this workspace.{' '}
          <Link href="/detection/coverage" className="text-blue-400 hover:text-blue-300">
            See the full ATT&amp;CK matrix
          </Link>
        </p>
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {summaryCards.map((c) => (
          <div key={c.label} className="rounded-xl border border-gray-800/60 bg-gray-900/40 p-4">
            <p className="text-xs text-gray-400 uppercase tracking-wider">{c.label}</p>
            <p className="mt-1 text-2xl font-semibold text-white">{c.value}</p>
          </div>
        ))}
      </div>

      {/* Gap Analysis Table */}
      <div className="rounded-xl border border-gray-800/60 bg-gray-900/40 overflow-hidden">
        <div className="px-5 py-4 border-b border-gray-800/60 flex flex-wrap items-center gap-3">
          <h2 className="text-lg font-semibold text-white flex-1 min-w-0">Gap Analysis</h2>
          <div className="flex gap-2">
            {(['all', 'gap', 'partial', 'covered'] as const).map((f) => (
              <button
                key={f}
                onClick={() => setStatusFilter(f)}
                className={clsx(
                  'text-xs px-3 py-1 rounded-lg border transition-colors',
                  statusFilter === f ? 'bg-blue-600/15 text-blue-300 border-blue-600/30' : 'text-gray-400 border-gray-800 hover:border-gray-700',
                )}
              >
                {f === 'all' ? 'All' : STATUS_STYLES[f as CoverageStatus].label}
              </button>
            ))}
          </div>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-800/60 text-left text-gray-400">
                <th className="px-5 py-3 font-medium">Technique</th>
                <th className="px-5 py-3 font-medium">Name</th>
                <th className="px-5 py-3 font-medium">Tactic</th>
                <th className="px-5 py-3 font-medium text-center">Coverage</th>
                <th className="px-5 py-3 font-medium text-center">Rules (active / total)</th>
                <th className="px-5 py-3 font-medium text-center">Priority</th>
                <th className="px-5 py-3 font-medium">Recommendation</th>
                <th className="px-5 py-3 font-medium text-center">Action</th>
              </tr>
            </thead>
            <tbody>
              {filteredTechniques.length === 0 ? (
                <tr>
                  <td colSpan={8} className="py-0">
                    <EmptyState
                      icon={EmptyStateIcons.shield}
                      title="No techniques match this filter"
                      description="Try selecting a different coverage status or view all techniques."
                      action={
                        <button
                          type="button"
                          onClick={() => setStatusFilter('all')}
                          className="rounded-lg bg-gray-800 px-4 py-2 text-sm text-gray-200 hover:bg-gray-700 transition-colors"
                        >
                          Show all techniques
                        </button>
                      }
                    />
                  </td>
                </tr>
              ) : (
                filteredTechniques.map((t) => {
                  const st = STATUS_STYLES[t.status];
                  const pr = PRIORITY[t.status];
                  return (
                    <tr key={t.id} className="border-b border-gray-800/40 hover:bg-gray-800/30 transition-colors">
                      <td className="px-5 py-3 font-mono text-blue-400 text-xs">{t.id}</td>
                      <td className="px-5 py-3 text-white">{t.name}</td>
                      <td className="px-5 py-3 text-gray-300">{t.tactic}</td>
                      <td className="px-5 py-3 text-center">
                        <span className={clsx('inline-block px-2.5 py-0.5 rounded-full text-xs font-medium', st.bg, st.text)}>{st.label}</span>
                      </td>
                      <td className="px-5 py-3 text-center text-gray-300">
                        {t.activeRules} / {t.totalRules}
                      </td>
                      <td className="px-5 py-3 text-center">
                        <span className={clsx('inline-block px-2.5 py-0.5 rounded-full text-xs font-medium', pr.bg, pr.text)}>{pr.label}</span>
                      </td>
                      <td className="px-5 py-3 text-gray-400 max-w-xs">{recommendation(t)}</td>
                      <td className="px-5 py-3 text-center">
                        {t.status !== 'covered' && (
                          <Link
                            href="/detection/new"
                            className="text-xs px-2.5 py-1 rounded-lg bg-blue-600 hover:bg-blue-500 text-white transition-colors whitespace-nowrap"
                          >
                            Create rule
                          </Link>
                        )}
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
