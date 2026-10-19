import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import {
  Fingerprint,
  Search,
  Filter,
  Download,
  ExternalLink,
  ShieldCheck,
  CheckCircle,
  XCircle,
  FileText,
  Clock,
  Sparkles,
  ArrowRight,
  RefreshCw,
  Plus,
  Copy,
  Check
} from 'lucide-react';

import { api } from '../services/api';
import { IndicatorDetail } from '../types';
import { IndicatorBadge } from '../components/IndicatorBadge';
import { LoadingSpinner } from '../components/LoadingSpinner';
import { EmptyState } from '../components/EmptyState';
import { useToast } from '../context/ToastContext';

export const IndicatorsPage: React.FC = () => {
  const { showToast } = useToast();
  const [indicators, setIndicators] = useState<IndicatorDetail[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  // Filters
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [typeFilter, setTypeFilter] = useState<string>('All');
  const [statusFilter, setStatusFilter] = useState<string>('All');

  // Selected indicator for detail drawer
  const [selectedInd, setSelectedInd] = useState<IndicatorDetail | null>(null);
  const [noteInput, setNoteInput] = useState<string>('');
  const [updating, setUpdating] = useState<boolean>(false);
  const [enriching, setEnriching] = useState<boolean>(false);
  const [enrichResult, setEnrichResult] = useState<any>(null);
  const [copiedIndicator, setCopiedIndicator] = useState<string | null>(null);

  const fetchIndicators = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await api.getIndicators({
        q: searchQuery,
        type: typeFilter,
        status: statusFilter,
      });
      setIndicators(data);
      if (selectedInd) {
        const updated = data.find((i) => i.id === selectedInd.id);
        if (updated) setSelectedInd(updated);
      }
    } catch (err: any) {
      setError(err.message || 'Failed to load indicators.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchIndicators();
  }, [typeFilter, statusFilter]);

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    fetchIndicators();
  };

  const handleCopyIndicator = (value: string, e?: React.MouseEvent) => {
    if (e) e.stopPropagation();
    navigator.clipboard.writeText(value);
    setCopiedIndicator(value);
    showToast(`Copied indicator "${value}" to clipboard`, 'success');
    setTimeout(() => setCopiedIndicator(null), 2000);
  };

  const handleStatusChange = async (newStatus: string) => {
    if (!selectedInd) return;
    setUpdating(true);
    try {
      const updated = await api.updateIndicator(selectedInd.id, newStatus, undefined);
      setSelectedInd(updated);
      showToast(`Indicator verification status set to "${newStatus}"`, 'success');
      await fetchIndicators();
    } catch (err: any) {
      setError(err.message);
      showToast(err.message || 'Status update failed.', 'error');
    } finally {
      setUpdating(false);
    }
  };

  const handleAddNote = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedInd || !noteInput.trim()) return;
    setUpdating(true);
    try {
      const updated = await api.updateIndicator(selectedInd.id, undefined, noteInput.trim());
      setSelectedInd(updated);
      setNoteInput('');
      showToast('Analyst note appended to indicator audit trail.', 'success');
      await fetchIndicators();
    } catch (err: any) {
      setError(err.message);
      showToast(err.message || 'Failed to save note.', 'error');
    } finally {
      setUpdating(false);
    }
  };

  const handleEnrich = async () => {
    if (!selectedInd) return;
    setEnriching(true);
    setEnrichResult(null);
    try {
      const res = await api.enrichIndicator(selectedInd.id);
      setEnrichResult(res);
      showToast(res.message || 'Enrichment query completed.', 'info');
      await fetchIndicators();
    } catch (err: any) {
      setError(err.message);
      showToast(err.message || 'Enrichment failed.', 'error');
    } finally {
      setEnriching(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Top Controls & Filter Bar */}
      <div className="flex flex-wrap items-center justify-between gap-4 rounded-lg bg-surface p-4 border border-border shadow-sm">
        <form onSubmit={handleSearchSubmit} className="flex-1 max-w-md relative">
          <Search className="absolute left-3 top-2.5 h-4 w-4 text-charcoal-400" />
          <input
            type="text"
            placeholder="Search indicator value (IP, domain, hash, CVE)..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full rounded-md border border-border bg-surface pl-9 pr-3 py-1.5 text-xs text-charcoal-900 placeholder-charcoal-400 focus:outline-none focus:ring-1 focus:ring-accent"
          />
        </form>

        <div className="flex flex-wrap items-center gap-3">
          <select
            value={typeFilter}
            onChange={(e) => setTypeFilter(e.target.value)}
            className="rounded-md border border-border bg-surface px-2.5 py-1.5 text-xs text-charcoal-700 focus:outline-none focus:ring-1 focus:ring-accent"
          >
            <option value="All">All Types</option>
            <option value="ipv4">IPv4</option>
            <option value="domain">Domain</option>
            <option value="url">URL</option>
            <option value="email">Email</option>
            <option value="sha256">SHA-256</option>
            <option value="sha1">SHA-1</option>
            <option value="md5">MD5</option>
            <option value="cve">CVE</option>
          </select>

          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="rounded-md border border-border bg-surface px-2.5 py-1.5 text-xs text-charcoal-700 focus:outline-none focus:ring-1 focus:ring-accent"
          >
            <option value="All">All Statuses</option>
            <option value="Unverified">Unverified</option>
            <option value="Analyst Confirmed">Analyst Confirmed</option>
            <option value="False Positive">False Positive</option>
          </select>

          <a
            href="/api/indicators/export/csv"
            download
            onClick={() => showToast('Downloading indicators CSV export...', 'info')}
            className="inline-flex items-center gap-1.5 rounded-md border border-border bg-surface px-3 py-1.5 text-xs font-semibold text-charcoal-700 hover:bg-surface-subtle transition"
          >
            <Download className="h-3.5 w-3.5" />
            <span>Export CSV</span>
          </a>
        </div>
      </div>

      {error && (
        <div className="rounded-md bg-red-50 border border-red-200 p-3.5 text-xs text-red-700">
          {error}
        </div>
      )}

      {loading && indicators.length === 0 ? (
        <LoadingSpinner message="Loading extracted indicators of compromise..." />
      ) : indicators.length === 0 ? (
        <EmptyState
          title="No Indicators Found"
          description="No indicators match your search or filter query. You can submit threat reports in the Analyze workspace."
        />
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Main Indicators Table (2 cols or 3 cols if no drawer) */}
          <div className={`rounded-lg bg-surface border border-border shadow-sm overflow-hidden ${selectedInd ? 'lg:col-span-2' : 'lg:col-span-3'}`}>
            <div className="border-b border-border px-5 py-3.5 flex items-center justify-between">
              <div>
                <h3 className="text-xs font-bold text-charcoal-900 uppercase tracking-wider">
                  Extracted Indicators Repository ({indicators.length})
                </h3>
                <p className="text-[11px] text-charcoal-500">Safely defanged technical tokens with triage statuses & evidence links</p>
              </div>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="bg-surface-subtle text-charcoal-600 border-b border-border font-medium">
                  <tr>
                    <th className="px-5 py-2.5">Indicator Value</th>
                    <th className="px-5 py-2.5">Type</th>
                    <th className="px-5 py-2.5">Reputation</th>
                    <th className="px-5 py-2.5 text-center">Reports</th>
                    <th className="px-5 py-2.5">Status</th>
                    <th className="px-5 py-2.5 text-right">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {indicators.map((ind) => {
                    const val = ind.defanged_value || ind.normalized_value;
                    const isCopied = copiedIndicator === val;

                    return (
                      <tr
                        key={ind.id}
                        onClick={() => { setSelectedInd(ind); setEnrichResult(null); }}
                        className={`cursor-pointer transition ${
                          selectedInd?.id === ind.id ? 'bg-accent/5' : 'hover:bg-surface-subtle/50'
                        }`}
                      >
                        <td className="px-5 py-2.5 font-mono font-medium text-charcoal-900 max-w-xs truncate">
                          <div className="flex items-center gap-2">
                            <button
                              type="button"
                              onClick={(e) => handleCopyIndicator(val, e)}
                              className="p-1 text-charcoal-400 hover:text-charcoal-800 transition rounded hover:bg-surface"
                              title="Copy defanged indicator"
                            >
                              {isCopied ? <Check className="h-3 w-3 text-emerald-600" /> : <Copy className="h-3 w-3" />}
                            </button>
                            <span className="truncate">{val}</span>
                          </div>
                        </td>
                        <td className="px-5 py-2.5">
                          <IndicatorBadge type={ind.indicator_type} size="sm" />
                        </td>
                        <td className="px-5 py-2.5 text-charcoal-600 max-w-xs truncate">
                          {ind.reputation_status}
                        </td>
                        <td className="px-5 py-2.5 text-center font-mono">
                          <span className="rounded-full bg-surface-subtle px-2 py-0.5 text-[11px] border border-border">
                            {ind.associated_reports_count}
                          </span>
                        </td>
                        <td className="px-5 py-2.5">
                          <span
                            className={`inline-flex items-center gap-1 text-[11px] font-medium px-2 py-0.5 rounded border ${
                              ind.verification_status === 'Analyst Confirmed'
                                ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
                                : ind.verification_status === 'False Positive'
                                ? 'bg-red-50 text-red-700 border-red-200'
                                : 'bg-slate-50 text-slate-700 border-slate-200'
                            }`}
                          >
                            {ind.verification_status}
                          </span>
                        </td>
                        <td className="px-5 py-2.5 text-right font-semibold text-accent hover:text-accent-hover">
                          Inspect
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>

          {/* Indicator Details Drawer (1 col) */}
          {selectedInd && (
            <div className="rounded-lg bg-surface border border-border p-5 shadow-sm space-y-5 animate-in fade-in duration-150">
              <div className="flex items-start justify-between border-b border-border pb-3">
                <div className="flex-1 pr-2">
                  <div className="flex items-center gap-2 mb-1.5">
                    <IndicatorBadge type={selectedInd.indicator_type} size="md" />
                    <span className="text-[10px] text-charcoal-400 font-mono">ID: {selectedInd.id.slice(0, 8)}</span>
                  </div>
                  <div className="flex items-center justify-between font-mono text-xs font-bold text-charcoal-900 break-all bg-surface-subtle p-2.5 rounded border border-border">
                    <span>{selectedInd.defanged_value || selectedInd.normalized_value}</span>
                    <button
                      type="button"
                      onClick={() => handleCopyIndicator(selectedInd.defanged_value || selectedInd.normalized_value)}
                      className="ml-2 p-1 text-charcoal-400 hover:text-charcoal-800 transition"
                      title="Copy indicator value"
                    >
                      <Copy className="h-3.5 w-3.5" />
                    </button>
                  </div>
                </div>
                <button
                  type="button"
                  onClick={() => setSelectedInd(null)}
                  className="text-xs text-charcoal-400 hover:text-charcoal-600 p-1 rounded hover:bg-surface-subtle"
                >
                  ✕
                </button>
              </div>

              {/* Status Controls */}
              <div>
                <label className="block text-xs font-semibold text-charcoal-700 mb-1.5">
                  Analyst Verification Status
                </label>
                <div className="grid grid-cols-3 gap-1.5 text-[11px]">
                  <button
                    type="button"
                    disabled={updating}
                    onClick={() => handleStatusChange('Unverified')}
                    className={`p-1.5 rounded border text-center font-medium transition ${
                      selectedInd.verification_status === 'Unverified'
                        ? 'bg-slate-800 text-white border-slate-800'
                        : 'border-border bg-surface text-charcoal-600 hover:bg-surface-subtle'
                    }`}
                  >
                    Unverified
                  </button>
                  <button
                    type="button"
                    disabled={updating}
                    onClick={() => handleStatusChange('Analyst Confirmed')}
                    className={`p-1.5 rounded border text-center font-medium transition ${
                      selectedInd.verification_status === 'Analyst Confirmed'
                        ? 'bg-emerald-700 text-white border-emerald-700'
                        : 'border-border bg-surface text-emerald-700 hover:bg-emerald-50'
                    }`}
                  >
                    Confirmed
                  </button>
                  <button
                    type="button"
                    disabled={updating}
                    onClick={() => handleStatusChange('False Positive')}
                    className={`p-1.5 rounded border text-center font-medium transition ${
                      selectedInd.verification_status === 'False Positive'
                        ? 'bg-red-700 text-white border-red-700'
                        : 'border-border bg-surface text-red-700 hover:bg-red-50'
                    }`}
                  >
                    False Pos.
                  </button>
                </div>
              </div>

              {/* External Threat Intelligence Enrichment */}
              <div className="rounded-md border border-border p-3.5 bg-surface-subtle/50 space-y-2">
                <div className="flex items-center justify-between">
                  <div className="text-xs font-semibold text-charcoal-900 flex items-center gap-1.5">
                    <Sparkles className="h-3.5 w-3.5 text-accent" />
                    External Enrichment
                  </div>
                  <button
                    type="button"
                    disabled={enriching}
                    onClick={handleEnrich}
                    className="inline-flex items-center gap-1 rounded bg-navy-900 px-2.5 py-1 text-[11px] font-medium text-white hover:bg-navy-800 disabled:opacity-50 transition"
                  >
                    {enriching ? <RefreshCw className="h-3 w-3 animate-spin" /> : 'Query Providers'}
                  </button>
                </div>
                <p className="text-[11px] text-charcoal-500">
                  Queries VirusTotal v3 and AlienVault OTX (sanitized query string only).
                </p>
                <div className="text-[11px] font-mono text-charcoal-700 bg-surface p-2 rounded border border-border">
                  Reputation: {selectedInd.reputation_status}
                </div>
                {enrichResult && (
                  <div className="text-[11px] p-2 rounded bg-surface border border-border text-charcoal-700">
                    {enrichResult.message || `Status: ${enrichResult.reputation_status}`}
                  </div>
                )}
              </div>

              {/* Associated Investigations */}
              <div>
                <h4 className="text-xs font-semibold text-charcoal-900 mb-2">
                  Associated Investigations ({selectedInd.associated_reports.length})
                </h4>
                <div className="space-y-2 max-h-40 overflow-y-auto pr-1">
                  {selectedInd.associated_reports.length === 0 ? (
                    <p className="text-xs text-charcoal-400">No linked investigations.</p>
                  ) : (
                    selectedInd.associated_reports.map((rep, idx) => (
                      <Link
                        key={idx}
                        to={`/reports?id=${rep.analysis_id}`}
                        className="block rounded border border-border bg-surface p-2 hover:bg-surface-subtle transition text-xs group"
                      >
                        <div className="font-semibold text-charcoal-900 group-hover:text-accent transition truncate">
                          {rep.title}
                        </div>
                        <div className="flex items-center justify-between text-[10px] text-charcoal-500 mt-1">
                          <span>{rep.category}</span>
                          <span>{new Date(rep.created_at).toLocaleDateString()}</span>
                        </div>
                      </Link>
                    ))
                  )}
                </div>
              </div>

              {/* Analyst Investigation Notes */}
              <div>
                <h4 className="text-xs font-semibold text-charcoal-900 mb-2">
                  Analyst Notes & Audit ({selectedInd.analyst_notes.length})
                </h4>
                <div className="space-y-2 max-h-36 overflow-y-auto pr-1 mb-2">
                  {selectedInd.analyst_notes.map((n) => (
                    <div key={n.id} className="text-xs p-2 rounded bg-surface-subtle border border-border">
                      <div className="flex items-center justify-between text-[10px] text-charcoal-400 mb-1">
                        <span className="font-medium text-charcoal-600">{n.author}</span>
                        <span>{new Date(n.created_at).toLocaleString()}</span>
                      </div>
                      <p className="text-charcoal-800">{n.note}</p>
                    </div>
                  ))}
                </div>

                <form onSubmit={handleAddNote} className="space-y-1.5">
                  <input
                    type="text"
                    placeholder="Add an analyst note..."
                    value={noteInput}
                    onChange={(e) => setNoteInput(e.target.value)}
                    className="w-full rounded border border-border bg-surface px-2.5 py-1.5 text-xs text-charcoal-900 placeholder-charcoal-400 focus:outline-none focus:ring-1 focus:ring-accent"
                  />
                  <button
                    type="submit"
                    disabled={updating || !noteInput.trim()}
                    className="w-full rounded bg-surface border border-border py-1 text-xs font-semibold text-charcoal-700 hover:bg-surface-subtle disabled:opacity-50 transition"
                  >
                    + Save Note
                  </button>
                </form>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
