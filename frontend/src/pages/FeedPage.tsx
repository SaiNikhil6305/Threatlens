import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Rss,
  Search,
  Filter,
  RefreshCw,
  ExternalLink,
  ShieldAlert,
  Calendar,
  Tag,
  ArrowRight,
  Crosshair,
  Sparkles
} from 'lucide-react';

import { api } from '../services/api';
import { IntelligenceFeedItem } from '../types';
import { SeverityBadge } from '../components/SeverityBadge';
import { LoadingSpinner } from '../components/LoadingSpinner';
import { EmptyState } from '../components/EmptyState';
import { useToast } from '../context/ToastContext';

export const FeedPage: React.FC = () => {
  const navigate = useNavigate();
  const { showToast } = useToast();
  const [feedItems, setFeedItems] = useState<IntelligenceFeedItem[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [syncing, setSyncing] = useState<boolean>(false);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  // Filters
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [categoryFilter, setCategoryFilter] = useState<string>('All');
  const [severityFilter, setSeverityFilter] = useState<string>('All');
  const [sourceFilter, setSourceFilter] = useState<string>('All');

  const fetchFeed = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await api.getFeed({
        q: searchQuery,
        category: categoryFilter,
        severity: severityFilter,
        source: sourceFilter,
      });
      setFeedItems(data);
    } catch (err: any) {
      setError(err.message || 'Failed to load intelligence feed.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchFeed();
  }, [categoryFilter, severityFilter, sourceFilter]);

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    fetchFeed();
  };

  const handleSyncCisa = async () => {
    setSyncing(true);
    setMessage(null);
    setError(null);
    showToast('Synchronizing CISA Known Exploited Vulnerabilities catalog...', 'info');
    try {
      const res = await api.syncCisaFeed();
      setMessage(res.message);
      showToast(res.message, 'success');
      await fetchFeed();
    } catch (err: any) {
      setError(err.message);
      showToast(err.message || 'Failed to sync CISA feed.', 'error');
    } finally {
      setSyncing(false);
    }
  };

  const handleAnalyzeFeedItem = (item: IntelligenceFeedItem) => {
    navigate('/analyze', {
      state: {
        title: item.title,
        text: item.summary,
        source: item.source
      }
    });
  };

  return (
    <div className="space-y-6">
      {/* Top Filter & Sync Controls */}
      <div className="flex flex-wrap items-center justify-between gap-4 rounded-lg bg-surface p-4 border border-border shadow-sm">
        <form onSubmit={handleSearchSubmit} className="flex-1 max-w-md relative">
          <Search className="absolute left-3 top-2.5 h-4 w-4 text-charcoal-400" />
          <input
            type="text"
            placeholder="Search security advisories, CVEs, or threat alerts..."
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
          </select>

          <button
            type="button"
            disabled={syncing}
            onClick={handleSyncCisa}
            className="inline-flex items-center gap-1.5 rounded-md bg-navy-900 px-3 py-1.5 text-xs font-semibold text-white shadow-sm hover:bg-navy-800 disabled:opacity-50 transition active:scale-[0.98]"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${syncing ? 'animate-spin' : ''}`} />
            <span>Sync CISA KEV Feed</span>
          </button>
        </div>
      </div>

      {message && (
        <div className="rounded-md bg-emerald-50 border border-emerald-200 p-3.5 text-xs text-emerald-800">
          {message}
        </div>
      )}

      {error && (
        <div className="rounded-md bg-red-50 border border-red-200 p-3.5 text-xs text-red-700">
          {error}
        </div>
      )}

      {loading && feedItems.length === 0 ? (
        <LoadingSpinner message="Querying intelligence feed repository..." />
      ) : feedItems.length === 0 ? (
        <EmptyState
          title="No Intelligence Feed Records"
          description="Your intelligence feed currently has no records. You can synchronize public CISA security advisories or submit threat reports in the Analyze workspace."
          actionText="Sync CISA KEV Advisories"
          onAction={handleSyncCisa}
        />
      ) : (
        <div className="space-y-4">
          {feedItems.map((item) => (
            <div
              key={item.id}
              className="rounded-lg bg-surface border border-border p-5 shadow-sm hover:border-border-strong transition space-y-3 interactive-card"
            >
              <div className="flex flex-wrap items-start justify-between gap-3">
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-surface-subtle text-charcoal-600 border border-border uppercase font-semibold">
                      {item.source}
                    </span>
                    <SeverityBadge severity={item.severity} size="sm" />
                    <span className="text-xs text-charcoal-400 font-medium">
                      {new Date(item.publication_date).toLocaleDateString()}
                    </span>
                  </div>
                  <h3 className="text-sm font-bold text-charcoal-900 tracking-tight">
                    {item.title}
                  </h3>
                </div>

                <div className="flex items-center gap-2">
                  <button
                    type="button"
                    onClick={() => handleAnalyzeFeedItem(item)}
                    className="inline-flex items-center gap-1.5 rounded-md border border-accent/30 bg-accent/5 px-2.5 py-1 text-xs font-semibold text-accent hover:bg-accent hover:text-white transition"
                    title="Send this advisory to the Threat Analysis Workspace"
                  >
                    <Crosshair className="h-3 w-3" />
                    <span>Analyze in Workspace</span>
                  </button>

                  {item.url && (
                    <a
                      href={item.url}
                      target="_blank"
                      rel="noreferrer"
                      className="inline-flex items-center gap-1 text-xs font-medium text-charcoal-500 hover:text-charcoal-800 p-1"
                    >
                      <span>Source</span>
                      <ExternalLink className="h-3 w-3" />
                    </a>
                  )}
                </div>
              </div>

              <p className="text-xs leading-relaxed text-charcoal-600">
                {item.summary}
              </p>

              {/* Indicators Tags */}
              {item.indicators && item.indicators.length > 0 && (
                <div className="flex flex-wrap items-center gap-1.5 pt-2 border-t border-border">
                  <span className="text-[10px] uppercase font-mono text-charcoal-400 mr-1">Extracted IoCs:</span>
                  {item.indicators.map((ioc, idx) => (
                    <span
                      key={idx}
                      className="font-mono text-[11px] bg-surface-subtle text-charcoal-700 px-2 py-0.5 rounded border border-border font-medium"
                    >
                      {ioc}
                    </span>
                  ))}
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
};
