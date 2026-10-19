import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import {
  FileText,
  Fingerprint,
  AlertTriangle,
  Tag,
  Clock,
  CheckCircle2,
  Filter,
  ArrowRight,
  TrendingUp,
  ShieldCheck,
  DownloadCloud,
  Crosshair,
  Rss,
  ShieldAlert,
  Activity,
  Sparkles
} from 'lucide-react';
import {
  ResponsiveContainer,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  PieChart,
  Pie,
  Cell,
  AreaChart,
  Area,
  CartesianGrid
} from 'recharts';

import { api } from '../services/api';
import { DashboardSummaryData } from '../types';
import { SeverityBadge } from '../components/SeverityBadge';
import { LoadingSpinner } from '../components/LoadingSpinner';
import { EmptyState } from '../components/EmptyState';
import { useToast } from '../context/ToastContext';

const SEVERITY_COLORS: Record<string, string> = {
  Critical: '#DC2626',
  High: '#EA580C',
  Medium: '#D97706',
  Low: '#16A34A',
  Informational: '#64748B',
};

export const OverviewPage: React.FC = () => {
  const { showToast } = useToast();
  const [data, setData] = useState<DashboardSummaryData | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  // Filters
  const [categoryFilter, setCategoryFilter] = useState<string>('All');
  const [severityFilter, setSeverityFilter] = useState<string>('All');
  const [daysFilter, setDaysFilter] = useState<number>(30);

  const fetchSummary = async () => {
    setLoading(true);
    setError(null);
    try {
      const summary = await api.getDashboardSummary({
        category: categoryFilter,
        severity: severityFilter,
        days: daysFilter,
      });
      setData(summary);
    } catch (err: any) {
      setError(err.message || 'Failed to load dashboard metrics.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchSummary();
  }, [categoryFilter, severityFilter, daysFilter]);

  const handleImportDemo = async () => {
    try {
      setLoading(true);
      await api.importDemoData();
      showToast('Demonstration dataset imported successfully.', 'success');
      await fetchSummary();
    } catch (err: any) {
      setError(err.message);
      showToast(err.message || 'Failed to import demonstration dataset.', 'error');
      setLoading(false);
    }
  };

  if (loading && !data) {
    return <LoadingSpinner message="Calculating database-backed metrics..." />;
  }

  const hasData = data && data.total_reports > 0;

  // Format chart data
  const categoryChartData = data
    ? Object.entries(data.category_distribution).map(([name, count]) => ({ name, count }))
    : [];

  const severityChartData = data
    ? Object.entries(data.severity_distribution).map(([name, value]) => ({ name, value }))
    : [];

  const indicatorChartData = data
    ? Object.entries(data.indicator_distribution).map(([type, count]) => ({
        type: type.toUpperCase(),
        count,
      }))
    : [];

  const highCriticalCount = data?.high_critical_count || 0;

  return (
    <div className="space-y-6">
      {/* Active Threat Posture Banner */}
      <div className={`rounded-lg p-4 border flex flex-wrap items-center justify-between gap-4 transition shadow-sm ${
        highCriticalCount > 0
          ? 'bg-red-500/5 border-red-500/20 text-red-950'
          : 'bg-emerald-500/5 border-emerald-500/20 text-emerald-950'
      }`}>
        <div className="flex items-center gap-3">
          <div className="relative flex h-3 w-3">
            <span className={`animate-ping absolute inline-flex h-full w-full rounded-full opacity-75 ${
              highCriticalCount > 0 ? 'bg-red-500' : 'bg-emerald-500'
            }`} />
            <span className={`relative inline-flex rounded-full h-3 w-3 ${
              highCriticalCount > 0 ? 'bg-red-600' : 'bg-emerald-600'
            }`} />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-xs font-bold uppercase tracking-wider">
                {highCriticalCount > 0 ? 'Threat Posture: Elevated Risk' : 'Threat Posture: Nominal / Active Monitoring'}
              </span>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-surface border border-border text-charcoal-700">
                {highCriticalCount} High/Critical finding{highCriticalCount === 1 ? '' : 's'}
              </span>
            </div>
            <p className="text-[11px] text-charcoal-600 mt-0.5">
              Live heuristic triage scoring active. MITRE ATT&CK correlation and local NLP engine online.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <Link
            to="/analyze"
            className="inline-flex items-center gap-1.5 rounded-md bg-navy-900 px-3 py-1.5 text-xs font-semibold text-white shadow-sm hover:bg-navy-800 transition active:scale-[0.98]"
          >
            <Crosshair className="h-3.5 w-3.5 text-accent" />
            <span>Analyze New Incident</span>
          </Link>
        </div>
      </div>

      {/* Quick Action Navigation Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <Link
          to="/analyze"
          className="rounded-lg bg-surface border border-border p-4 shadow-sm interactive-card group"
        >
          <div className="flex items-center justify-between mb-2">
            <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-accent/10 text-accent group-hover:bg-accent group-hover:text-white transition">
              <Crosshair className="h-4 w-4" />
            </div>
            <ArrowRight className="h-3.5 w-3.5 text-charcoal-400 group-hover:text-accent group-hover:translate-x-0.5 transition" />
          </div>
          <div className="text-xs font-bold text-charcoal-900 group-hover:text-accent transition">
            Analyze Threat Narrative
          </div>
          <p className="text-[11px] text-charcoal-500 mt-0.5">
            Extract IoCs, predict taxonomy & compute severity
          </p>
        </Link>

        <Link
          to="/indicators"
          className="rounded-lg bg-surface border border-border p-4 shadow-sm interactive-card group"
        >
          <div className="flex items-center justify-between mb-2">
            <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-indigo-50 text-indigo-600 group-hover:bg-indigo-600 group-hover:text-white transition">
              <Fingerprint className="h-4 w-4" />
            </div>
            <ArrowRight className="h-3.5 w-3.5 text-charcoal-400 group-hover:text-indigo-600 group-hover:translate-x-0.5 transition" />
          </div>
          <div className="text-xs font-bold text-charcoal-900 group-hover:text-indigo-600 transition">
            Indicators Repository
          </div>
          <p className="text-[11px] text-charcoal-500 mt-0.5">
            {data?.total_indicators || 0} normalized & defanged technical IoCs
          </p>
        </Link>

        <Link
          to="/feed"
          className="rounded-lg bg-surface border border-border p-4 shadow-sm interactive-card group"
        >
          <div className="flex items-center justify-between mb-2">
            <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-emerald-50 text-emerald-600 group-hover:bg-emerald-600 group-hover:text-white transition">
              <Rss className="h-4 w-4" />
            </div>
            <ArrowRight className="h-3.5 w-3.5 text-charcoal-400 group-hover:text-emerald-600 group-hover:translate-x-0.5 transition" />
          </div>
          <div className="text-xs font-bold text-charcoal-900 group-hover:text-emerald-600 transition">
            Intelligence Feed
          </div>
          <p className="text-[11px] text-charcoal-500 mt-0.5">
            Multi-source advisories & CISA KEV alerts
          </p>
        </Link>

        <Link
          to="/techniques"
          className="rounded-lg bg-surface border border-border p-4 shadow-sm interactive-card group"
        >
          <div className="flex items-center justify-between mb-2">
            <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-purple-50 text-purple-600 group-hover:bg-purple-600 group-hover:text-white transition">
              <ShieldAlert className="h-4 w-4" />
            </div>
            <ArrowRight className="h-3.5 w-3.5 text-charcoal-400 group-hover:text-purple-600 group-hover:translate-x-0.5 transition" />
          </div>
          <div className="text-xs font-bold text-charcoal-900 group-hover:text-purple-600 transition">
            MITRE ATT&CK Matrix
          </div>
          <p className="text-[11px] text-charcoal-500 mt-0.5">
            Adversary technique mappings & correlation
          </p>
        </Link>
      </div>

      {/* Filter Bar */}
      <div className="flex flex-wrap items-center justify-between gap-4 rounded-lg bg-surface p-4 border border-border shadow-2xs">
        <div className="flex items-center gap-2 text-xs font-semibold text-charcoal-700">
          <Filter className="h-4 w-4 text-accent" />
          <span>Dashboard Filters</span>
        </div>

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
            <option value="Web Application Attack">Web Application Attack</option>
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
            value={daysFilter}
            onChange={(e) => setDaysFilter(Number(e.target.value))}
            className="rounded-md border border-border bg-surface px-2.5 py-1.5 text-xs text-charcoal-700 focus:outline-none focus:ring-1 focus:ring-accent"
          >
            <option value={7}>Last 7 Days</option>
            <option value={30}>Last 30 Days</option>
            <option value={90}>Last 90 Days</option>
            <option value={365}>All Time</option>
          </select>
        </div>
      </div>

      {error && (
        <div className="rounded-md bg-red-50 border border-red-200 p-4 text-xs text-red-700">
          {error}
        </div>
      )}

      {/* Summary KPI Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
        <div className="rounded-lg bg-surface border border-border p-4 shadow-sm interactive-card">
          <div className="flex items-center justify-between text-charcoal-500 mb-2">
            <span className="text-xs font-medium">Total Analyzed Reports</span>
            <FileText className="h-4 w-4 text-accent" />
          </div>
          <div className="text-2xl font-bold text-charcoal-900 tracking-tight font-mono">
            {data?.total_reports || 0}
          </div>
          <p className="text-[11px] text-charcoal-400 mt-1">Stored in SQLite database</p>
        </div>

        <div className="rounded-lg bg-surface border border-border p-4 shadow-sm interactive-card">
          <div className="flex items-center justify-between text-charcoal-500 mb-2">
            <span className="text-xs font-medium">Unique Indicators</span>
            <Fingerprint className="h-4 w-4 text-indigo-600" />
          </div>
          <div className="text-2xl font-bold text-charcoal-900 tracking-tight font-mono">
            {data?.total_indicators || 0}
          </div>
          <p className="text-[11px] text-charcoal-400 mt-1">IPs, domains, hashes, CVEs</p>
        </div>

        <div className="rounded-lg bg-surface border border-border p-4 shadow-sm interactive-card">
          <div className="flex items-center justify-between text-charcoal-500 mb-2">
            <span className="text-xs font-medium">High & Critical Findings</span>
            <AlertTriangle className="h-4 w-4 text-severity-high" />
          </div>
          <div className="text-2xl font-bold text-charcoal-900 tracking-tight font-mono text-red-600">
            {data?.high_critical_count || 0}
          </div>
          <p className="text-[11px] text-charcoal-400 mt-1">Immediate triage priority</p>
        </div>

        <div className="rounded-lg bg-surface border border-border p-4 shadow-sm interactive-card">
          <div className="flex items-center justify-between text-charcoal-500 mb-2">
            <span className="text-xs font-medium">Top Threat Category</span>
            <Tag className="h-4 w-4 text-emerald-600" />
          </div>
          <div className="text-base font-semibold text-charcoal-900 truncate mt-1">
            {data?.top_threat_category || 'None'}
          </div>
          <p className="text-[11px] text-charcoal-400 mt-1">Most frequent classification</p>
        </div>

        <div className="rounded-lg bg-surface border border-border p-4 shadow-sm interactive-card">
          <div className="flex items-center justify-between text-charcoal-500 mb-2">
            <span className="text-xs font-medium">Awaiting Review</span>
            <Clock className="h-4 w-4 text-amber-600" />
          </div>
          <div className="text-2xl font-bold text-charcoal-900 tracking-tight font-mono">
            {data?.pending_review_count || 0}
          </div>
          <p className="text-[11px] text-charcoal-400 mt-1">Unverified indicators</p>
        </div>
      </div>

      {!hasData ? (
        <EmptyState
          title="No Threat Intelligence Records Yet"
          description="Your local database is currently empty. Analyze your first unstructured threat report or import the synthetic demonstration scenarios."
          actionText="Import Demonstration Dataset"
          onAction={handleImportDemo}
        />
      ) : (
        <>
          {/* Charts Row */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Chart 1: Threat Category Distribution */}
            <div className="rounded-lg bg-surface border border-border p-5 shadow-sm lg:col-span-2">
              <div className="flex items-center justify-between mb-4">
                <div>
                  <h3 className="text-sm font-semibold text-charcoal-900">Threat Category Distribution</h3>
                  <p className="text-xs text-charcoal-500">Classification frequency across analyzed reports</p>
                </div>
              </div>
              <div className="h-64">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={categoryChartData} margin={{ top: 10, right: 10, left: -20, bottom: 40 }}>
                    <defs>
                      <linearGradient id="blueGradient" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="0%" stopColor="#2563EB" stopOpacity={0.9} />
                        <stop offset="100%" stopColor="#1E40AF" stopOpacity={0.7} />
                      </linearGradient>
                    </defs>
                    <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="#F1F5F9" />
                    <XAxis
                      dataKey="name"
                      tick={{ fontSize: 10, fill: '#64748B' }}
                      angle={-25}
                      textAnchor="end"
                      interval={0}
                    />
                    <YAxis tick={{ fontSize: 10, fill: '#64748B' }} allowDecimals={false} />
                    <Tooltip
                      contentStyle={{
                        backgroundColor: '#0F172A',
                        borderColor: '#334155',
                        color: '#FFF',
                        borderRadius: '8px',
                        fontSize: '12px',
                        boxShadow: '0 10px 15px -3px rgba(0, 0, 0, 0.3)'
                      }}
                    />
                    <Bar dataKey="count" fill="url(#blueGradient)" radius={[4, 4, 0, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </div>

            {/* Chart 2: Severity Distribution */}
            <div className="rounded-lg bg-surface border border-border p-5 shadow-sm">
              <div className="flex items-center justify-between mb-4">
                <div>
                  <h3 className="text-sm font-semibold text-charcoal-900">Severity Distribution</h3>
                  <p className="text-xs text-charcoal-500">Calculated triage severity tiers</p>
                </div>
              </div>
              <div className="h-64 flex items-center justify-center">
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={severityChartData.filter((d) => d.value > 0)}
                      cx="50%"
                      cy="50%"
                      innerRadius={52}
                      outerRadius={82}
                      paddingAngle={3}
                      dataKey="value"
                    >
                      {severityChartData.map((entry) => (
                        <Cell key={entry.name} fill={SEVERITY_COLORS[entry.name] || '#94A3B8'} />
                      ))}
                    </Pie>
                    <Tooltip
                      contentStyle={{
                        backgroundColor: '#0F172A',
                        borderColor: '#334155',
                        color: '#FFF',
                        borderRadius: '8px',
                        fontSize: '12px'
                      }}
                    />
                  </PieChart>
                </ResponsiveContainer>
              </div>
              {/* Legend */}
              <div className="flex flex-wrap items-center justify-center gap-3 text-xs text-charcoal-600 mt-2">
                {Object.entries(SEVERITY_COLORS).map(([name, color]) => (
                  <div key={name} className="flex items-center gap-1.5">
                    <span className="h-2 w-2 rounded-full" style={{ backgroundColor: color }} />
                    <span className="text-[11px] font-medium">{name}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Activity Over Time & Indicators Breakdown */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            <div className="rounded-lg bg-surface border border-border p-5 shadow-sm lg:col-span-2">
              <div className="flex items-center justify-between mb-4">
                <div>
                  <h3 className="text-sm font-semibold text-charcoal-900">Analysis Activity Timeline</h3>
                  <p className="text-xs text-charcoal-500">Reports analyzed over the past 14 days</p>
                </div>
              </div>
              <div className="h-56">
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={data?.activity_timeline || []} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                    <defs>
                      <linearGradient id="areaGradient" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#2563EB" stopOpacity={0.3} />
                        <stop offset="95%" stopColor="#2563EB" stopOpacity={0.0} />
                      </linearGradient>
                    </defs>
                    <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="#F1F5F9" />
                    <XAxis dataKey="date" tick={{ fontSize: 10, fill: '#64748B' }} />
                    <YAxis tick={{ fontSize: 10, fill: '#64748B' }} allowDecimals={false} />
                    <Tooltip
                      contentStyle={{
                        backgroundColor: '#0F172A',
                        borderColor: '#334155',
                        color: '#FFF',
                        borderRadius: '8px',
                        fontSize: '12px'
                      }}
                    />
                    <Area type="monotone" dataKey="count" stroke="#2563EB" strokeWidth={2} fillOpacity={1} fill="url(#areaGradient)" />
                  </AreaChart>
                </ResponsiveContainer>
              </div>
            </div>

            <div className="rounded-lg bg-surface border border-border p-5 shadow-sm">
              <div className="flex items-center justify-between mb-4">
                <div>
                  <h3 className="text-sm font-semibold text-charcoal-900">Indicator Distribution</h3>
                  <p className="text-xs text-charcoal-500">Counts across technical indicator types</p>
                </div>
              </div>
              <div className="h-56">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={indicatorChartData} layout="vertical" margin={{ top: 5, right: 10, left: 15, bottom: 5 }}>
                    <CartesianGrid strokeDasharray="3 3" horizontal={false} stroke="#F1F5F9" />
                    <XAxis type="number" tick={{ fontSize: 10, fill: '#64748B' }} allowDecimals={false} />
                    <YAxis dataKey="type" type="category" tick={{ fontSize: 10, fill: '#64748B' }} width={50} />
                    <Tooltip
                      contentStyle={{
                        backgroundColor: '#0F172A',
                        borderColor: '#334155',
                        color: '#FFF',
                        borderRadius: '8px',
                        fontSize: '12px'
                      }}
                    />
                    <Bar dataKey="count" fill="#3B82F6" radius={[0, 4, 4, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </div>
          </div>

          {/* Recent Investigations Table */}
          <div className="rounded-lg bg-surface border border-border shadow-sm overflow-hidden">
            <div className="flex items-center justify-between border-b border-border px-5 py-4">
              <div>
                <h3 className="text-sm font-semibold text-charcoal-900">Recent Investigations</h3>
                <p className="text-xs text-charcoal-500">Latest threat analyses recorded in database</p>
              </div>
              <Link
                to="/history"
                className="inline-flex items-center gap-1 text-xs font-semibold text-accent hover:text-accent-hover transition"
              >
                <span>View Full History</span>
                <ArrowRight className="h-3.5 w-3.5" />
              </Link>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="bg-surface-subtle text-charcoal-600 border-b border-border font-medium">
                  <tr>
                    <th className="px-5 py-3">Analysis ID</th>
                    <th className="px-5 py-3">Investigation Title</th>
                    <th className="px-5 py-3">Threat Category</th>
                    <th className="px-5 py-3">Severity</th>
                    <th className="px-5 py-3 text-center">IoCs</th>
                    <th className="px-5 py-3">Created</th>
                    <th className="px-5 py-3 text-right">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {data?.recent_investigations.map((item) => (
                    <tr key={item.id} className="table-row-hover">
                      <td className="px-5 py-3 font-mono text-charcoal-500">
                        {item.id.slice(0, 8)}...
                      </td>
                      <td className="px-5 py-3 font-medium text-charcoal-900 max-w-xs truncate">
                        {item.title}
                      </td>
                      <td className="px-5 py-3 text-charcoal-700">
                        {item.predicted_category}
                      </td>
                      <td className="px-5 py-3">
                        <SeverityBadge severity={item.severity} size="sm" />
                      </td>
                      <td className="px-5 py-3 text-center font-mono">
                        <span className="px-2 py-0.5 rounded-full bg-surface-subtle text-charcoal-700 border border-border text-[11px]">
                          {item.indicator_count}
                        </span>
                      </td>
                      <td className="px-5 py-3 text-charcoal-500 font-mono text-[11px]">
                        {new Date(item.created_at).toLocaleDateString()}
                      </td>
                      <td className="px-5 py-3 text-right">
                        <Link
                          to={`/reports?id=${item.id}`}
                          className="inline-flex items-center gap-1 font-semibold text-accent hover:text-accent-hover"
                        >
                          <span>Report</span>
                          <ArrowRight className="h-3 w-3" />
                        </Link>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </>
      )}
    </div>
  );
};
