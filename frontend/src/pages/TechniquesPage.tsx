import React, { useEffect, useState } from 'react';
import {
  ShieldAlert,
  Search,
  Filter,
  ExternalLink,
  Layers,
  CheckCircle2,
  BookOpen
} from 'lucide-react';

import { api } from '../services/api';
import { AttackTechniqueRef } from '../types';
import { LoadingSpinner } from '../components/LoadingSpinner';
import { EmptyState } from '../components/EmptyState';

const TACTICS_LIST = [
  'All',
  'Initial Access',
  'Execution',
  'Persistence',
  'Privilege Escalation',
  'Defense Evasion',
  'Credential Access',
  'Discovery',
  'Lateral Movement',
  'Command and Control',
  'Exfiltration',
  'Impact'
];

export const TechniquesPage: React.FC = () => {
  const [techniques, setTechniques] = useState<AttackTechniqueRef[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  const [searchQuery, setSearchQuery] = useState<string>('');
  const [tacticFilter, setTacticFilter] = useState<string>('All');

  const fetchTechniques = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await api.getTechniques({
        q: searchQuery,
        tactic: tacticFilter,
      });
      setTechniques(data);
    } catch (err: any) {
      setError(err.message || 'Failed to load MITRE ATT&CK techniques.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchTechniques();
  }, [tacticFilter]);

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    fetchTechniques();
  };

  return (
    <div className="space-y-6">
      {/* Top Filter Bar */}
      <div className="flex flex-wrap items-center justify-between gap-4 rounded-lg bg-surface p-4 border border-border shadow-sm">
        <form onSubmit={handleSearchSubmit} className="flex-1 max-w-md relative">
          <Search className="absolute left-3 top-2.5 h-4 w-4 text-charcoal-400" />
          <input
            type="text"
            placeholder="Search technique ID (e.g. T1566) or name..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full rounded-md border border-border bg-surface pl-9 pr-3 py-1.5 text-xs text-charcoal-900 placeholder-charcoal-400 focus:outline-none focus:ring-1 focus:ring-accent"
          />
        </form>

        <div className="flex flex-wrap items-center gap-3">
          <select
            value={tacticFilter}
            onChange={(e) => setTacticFilter(e.target.value)}
            className="rounded-md border border-border bg-surface px-2.5 py-1.5 text-xs text-charcoal-700 focus:outline-none focus:ring-1 focus:ring-accent"
          >
            {TACTICS_LIST.map((tac) => (
              <option key={tac} value={tac}>
                {tac === 'All' ? 'All Tactics' : tac}
              </option>
            ))}
          </select>
        </div>
      </div>

      {error && (
        <div className="rounded-md bg-red-50 border border-red-200 p-3.5 text-xs text-red-700">
          {error}
        </div>
      )}

      {loading && techniques.length === 0 ? (
        <LoadingSpinner message="Querying reference MITRE ATT&CK database..." />
      ) : techniques.length === 0 ? (
        <EmptyState
          title="No MITRE Techniques Found"
          description="No techniques match your search query."
        />
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {techniques.map((tech) => (
            <div
              key={tech.id}
              className="rounded-lg bg-surface border border-border p-5 shadow-sm hover:border-border-strong transition flex flex-col justify-between space-y-3"
            >
              <div>
                <div className="flex items-center justify-between mb-2">
                  <span className="font-mono text-xs font-bold text-accent bg-accent/5 px-2 py-0.5 rounded border border-accent/20">
                    {tech.technique_id}
                  </span>
                  <span className="rounded bg-surface-subtle text-charcoal-600 px-2 py-0.5 text-[10px] font-medium border border-border">
                    {tech.tactic}
                  </span>
                </div>

                <h3 className="text-sm font-bold text-charcoal-900 mb-1.5">
                  {tech.technique_name}
                </h3>

                <p className="text-xs text-charcoal-600 leading-relaxed line-clamp-3">
                  {tech.description}
                </p>
              </div>

              <div className="flex items-center justify-between pt-3 border-t border-border text-xs">
                <div className="flex items-center gap-1.5 text-charcoal-500">
                  <span className="text-[11px]">Matched in:</span>
                  <span className="font-mono font-semibold text-charcoal-800">
                    {tech.investigation_count} {tech.investigation_count === 1 ? 'report' : 'reports'}
                  </span>
                </div>

                {tech.url && (
                  <a
                    href={tech.url}
                    target="_blank"
                    rel="noreferrer"
                    className="inline-flex items-center gap-1 font-medium text-accent hover:text-accent-hover text-[11px]"
                  >
                    <span>MITRE Matrix</span>
                    <ExternalLink className="h-3 w-3" />
                  </a>
                )}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};
