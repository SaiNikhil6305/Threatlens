import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import {
  History,
  Search,
  Filter,
  Trash2,
  ExternalLink,
  ArrowRight,
  FileText,
  Clock,
  AlertTriangle,
  Copy,
  Check
} from 'lucide-react';

import { api } from '../services/api';
import { AnalysisSummary } from '../types';
import { SeverityBadge } from '../components/SeverityBadge';
import { LoadingSpinner } from '../components/LoadingSpinner';
import { EmptyState } from '../components/EmptyState';
import { ConfirmationModal } from '../components/ConfirmationModal';
import { useToast } from '../context/ToastContext';

export const HistoryPage: React.FC = () => {
  const { showToast } = useToast();
  const [analyses, setAnalyses] = useState<AnalysisSummary[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  // Filters
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [categoryFilter, setCategoryFilter] = useState<string>('All');
  const [severityFilter, setSeverityFilter] = useState<string>('All');
  const [statusFilter, setStatusFilter] = useState<string>('All');

  // Deletion modal state
  const [deleteTarget, setDeleteTarget] = useState<AnalysisSummary | null>(null);
  const [deleting, setDeleting] = useState<boolean>(false);
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const fetchAnalyses = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await api.getAnalyses({
        q: searchQuery,
        category: categoryFilter,
        severity: severityFilter,
        status: statusFilter,
        limit: 100,
      });
      setAnalyses(data);
    } catch (err: any) {
      setError(err.message || 'Failed to load analysis history.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAnalyses();
  }, [categoryFilter, severityFilter, statusFilter]);

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    fetchAnalyses();
  };

  const handleCopyId = (id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    navigator.clipboard.writeText(id);
    setCopiedId(id);
    showToast(`Copied analysis ID "${id.slice(0, 8)}" to clipboard`, 'success');
    setTimeout(() => setCopiedId(null), 2000);
  };

  const handleConfirmDelete = async () => {
    if (!deleteTarget) return;
    setDeleting(true);
    try {
      await api.deleteAnalysis(deleteTarget.id);
      showToast(`Investigation "${deleteTarget.title}" deleted.`, 'success');
      setDeleteTarget(null);
      await fetchAnalyses();
    } catch (err: any) {
      setError(err.message || 'Failed to delete analysis.');
      showToast(err.message || 'Failed to delete analysis.', 'error');
    } finally {
      setDeleting(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Search & Filter Controls */}
      <div className="flex flex-wrap items-center justify-between gap-4 rounded-lg bg-surface p-4 border border-border shadow-sm">
        <form onSubmit={handleSearchSubmit} className="flex-1 max-w-md relative">
          <Search className="absolute left-3 top-2.5 h-4 w-4 text-charcoal-400" />
          <input
            type="text"
            placeholder="Search analysis title or narrative content..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full rounded-md border border-border bg-surface pl-9 pr-3 py-1.5 text-xs text-charcoal-900 placeholder-charcoal-400 focus:outline-none focus:ring-1 focus:ring-accent"
          />
        </form>

        <div className="flex flex-wrap items-center gap-3">
          <select
            value={categoryFilter}
            onChange={(e) => setCategoryFilter(e.target.value)}
            className="rounded-md border border-border bg-surface px-2.5 py-1.5 text-xs text-charcoal-700 focus:outline-none focus:ring-1 focus:ring-accent"
          >
            <option value="All">All Categories</option>
            <option value="Phishing">Phishing</option>
            <option value="Malware">Malware</option>
            <option value="Ransomware">Ransomware</option>
            <option value="Credential Theft">Credential Theft</option>
            <option value="Vulnerability Exploitation">Vulnerability Exploitation</option>
            <option value="Data Exfiltration">Data Exfiltration</option>
            <option value="Denial of Service">Denial of Service</option>
            <option value="Reconnaissance">Reconnaissance</option>
            <option value="Benign or Informational">Benign or Informational</option>
          </select>

          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="rounded-md border border-border bg-surface px-2.5 py-1.5 text-xs text-charcoal-700 focus:outline-none focus:ring-1 focus:ring-accent"
          >
            <option value="All">All Severities</option>
            <option value="Critical">Critical</option>
            <option value="High">High</option>
            <option value="Medium">Medium</option>
            <option value="Low">Low</option>
            <option value="Informational">Informational</option>
          </select>

          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="rounded-md border border-border bg-surface px-2.5 py-1.5 text-xs text-charcoal-700 focus:outline-none focus:ring-1 focus:ring-accent"
          >
            <option value="All">All Statuses</option>
            <option value="Completed">Completed</option>
            <option value="Review Pending">Review Pending</option>
          </select>
        </div>
      </div>

      {error && (
        <div className="rounded-md bg-red-50 border border-red-200 p-3.5 text-xs text-red-700">
          {error}
        </div>
      )}

      {loading && analyses.length === 0 ? (
        <LoadingSpinner message="Querying database analysis records..." />
      ) : analyses.length === 0 ? (
        <EmptyState
          title="No Analysis Records Found"
          description="No investigations match your query. You can run new analyses in the Threat Analysis Workspace."
        />
      ) : (
        <div className="rounded-lg bg-surface border border-border shadow-sm overflow-hidden">
          <div className="border-b border-border px-5 py-3.5 flex items-center justify-between">
            <h3 className="text-xs font-bold text-charcoal-900 uppercase tracking-wider">
              Recorded Investigations Repository ({analyses.length})
            </h3>
            <span className="text-xs text-charcoal-500 font-mono">SQLite Persistent Store</span>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-surface-subtle text-charcoal-600 border-b border-border font-medium">
                <tr>
                  <th className="px-5 py-3">Analysis ID</th>
                  <th className="px-5 py-3">Investigation Title</th>
                  <th className="px-5 py-3">Type</th>
                  <th className="px-5 py-3">Threat Category</th>
                  <th className="px-5 py-3">Severity</th>
                  <th className="px-5 py-3 text-center">IoCs</th>
                  <th className="px-5 py-3">Timestamp</th>
                  <th className="px-5 py-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {analyses.map((item) => {
                  const isCopied = copiedId === item.id;
                  return (
                    <tr key={item.id} className="table-row-hover">
                      <td className="px-5 py-3 font-mono text-charcoal-500">
                        <div className="flex items-center gap-1.5">
                          <button
                            type="button"
                            onClick={(e) => handleCopyId(item.id, e)}
                            className="p-1 text-charcoal-400 hover:text-charcoal-800 transition rounded"
                            title="Copy full analysis ID"
                          >
                            {isCopied ? <Check className="h-3 w-3 text-emerald-600" /> : <Copy className="h-3 w-3" />}
                          </button>
                          <span>{item.id.slice(0, 8)}...</span>
                        </div>
                      </td>
                      <td className="px-5 py-3 font-semibold text-charcoal-900 max-w-xs truncate">
                        {item.title}
                      </td>
                      <td className="px-5 py-3 text-charcoal-600 capitalize">
                        {item.input_type}
                      </td>
                      <td className="px-5 py-3 text-charcoal-700">
                        {item.predicted_category}
                      </td>
                      <td className="px-5 py-3">
                        <SeverityBadge severity={item.severity} size="sm" />
                      </td>
                      <td className="px-5 py-3 text-center font-mono">
                        <span className="px-2 py-0.5 rounded-full bg-surface-subtle text-charcoal-700 border border-border text-[11px]">
                          {item.indicators_count}
                        </span>
                      </td>
                      <td className="px-5 py-3 text-charcoal-500 font-mono text-[11px]">
                        {new Date(item.created_at).toLocaleString()}
                      </td>
                      <td className="px-5 py-3 text-right">
                        <div className="inline-flex items-center gap-3">
                          <Link
                            to={`/reports?id=${item.id}`}
                            className="font-semibold text-accent hover:text-accent-hover inline-flex items-center gap-1"
                          >
                            <span>Report</span>
                            <ArrowRight className="h-3 w-3" />
                          </Link>
                          <button
                            type="button"
                            onClick={() => setDeleteTarget(item)}
                            className="text-charcoal-400 hover:text-red-600 transition p-1 rounded hover:bg-red-50"
                            title="Delete Analysis"
                          >
                            <Trash2 className="h-3.5 w-3.5" />
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Confirmation Modal */}
      <ConfirmationModal
        isOpen={Boolean(deleteTarget)}
        title="Delete Threat Analysis"
        message={`Are you sure you want to permanently delete investigation '${deleteTarget?.title}'? This will remove associated extracted indicators and evidence snippets.`}
        confirmText={deleting ? 'Deleting...' : 'Delete Permanently'}
        onConfirm={handleConfirmDelete}
        onCancel={() => setDeleteTarget(null)}
      />
    </div>
  );
};
