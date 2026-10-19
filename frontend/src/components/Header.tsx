import React, { useState } from 'react';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import { Plus, Database, Search, Shield, Command, ArrowRight } from 'lucide-react';

interface HeaderProps {
  systemHealth?: {
    status: string;
    database: string;
    ml_model_loaded: boolean;
  };
}

export const Header: React.FC<HeaderProps> = ({ systemHealth }) => {
  const location = useLocation();
  const navigate = useNavigate();
  const [quickSearch, setQuickSearch] = useState('');

  const getPageTitle = (pathname: string) => {
    switch (pathname) {
      case '/': return { title: 'Operational Overview', subtitle: 'Real-time telemetry, threat distribution & active investigations' };
      case '/analyze': return { title: 'Threat Analysis Workspace', subtitle: 'Natural Language Processing, IoC extraction & explainable triage' };
      case '/feed': return { title: 'Intelligence Feed', subtitle: 'Multi-source security bulletins, advisories & CISA KEV alerts' };
      case '/indicators': return { title: 'Indicator Intelligence Repository', subtitle: 'Normalized technical IoCs, correlation links & verification statuses' };
      case '/techniques': return { title: 'MITRE ATT&CK Matrix', subtitle: 'Adversary tactics, techniques & ThreatLens evidence mappings' };
      case '/reports': return { title: 'Formal Intelligence Reports', subtitle: '10-section intelligence briefings, executive summaries & multi-format exports' };
      case '/history': return { title: 'Investigation History', subtitle: 'Searchable audit repository of saved threat assessments' };
      case '/model-evaluation': return { title: 'Academic Model Evaluation', subtitle: 'TF-IDF supervised classification benchmarks, confusion matrices & metrics' };
      case '/settings': return { title: 'Platform Settings & Feeds', subtitle: 'Provider integrations, database parameters & demonstration dataset' };
      default: return { title: 'ThreatLens Workbench', subtitle: 'See Beyond the Threat' };
    }
  };

  const { title, subtitle } = getPageTitle(location.pathname);

  const handleQuickSearch = (e: React.FormEvent) => {
    e.preventDefault();
    if (quickSearch.trim()) {
      navigate(`/history?q=${encodeURIComponent(quickSearch.trim())}`);
      setQuickSearch('');
    }
  };

  return (
    <header className="h-16 flex-shrink-0 flex items-center justify-between border-b border-border bg-surface/90 backdrop-blur-md px-8 sticky top-0 z-10 select-none">
      <div>
        <h1 className="text-sm font-bold text-charcoal-900 tracking-tight flex items-center gap-2">
          {title}
        </h1>
        <p className="text-[11px] text-charcoal-400 font-medium">{subtitle}</p>
      </div>

      <div className="flex items-center gap-3">
        {/* Quick Search */}
        <form onSubmit={handleQuickSearch} className="hidden sm:flex items-center relative">
          <Search className="absolute left-2.5 top-2 h-3.5 w-3.5 text-charcoal-400" />
          <input
            type="text"
            placeholder="Search investigations..."
            value={quickSearch}
            onChange={(e) => setQuickSearch(e.target.value)}
            className="w-48 lg:w-64 rounded-md border border-border bg-surface pl-8 pr-12 py-1.5 text-xs text-charcoal-900 placeholder-charcoal-400 focus:outline-none focus:ring-1 focus:ring-accent focus:w-72 transition-all shadow-2xs"
          />
          <kbd className="absolute right-2 top-2 text-[9px] font-mono font-semibold px-1 py-0.2 rounded bg-surface-subtle text-charcoal-400 border border-border pointer-events-none">
            Ctrl+K
          </kbd>
        </form>

        {/* Database Status */}
        <div className="hidden md:flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-surface-subtle border border-border text-[11px] text-charcoal-600 font-medium shadow-2xs">
          <span className="h-1.5 w-1.5 rounded-full bg-emerald-500" />
          <span className="font-mono text-[10px]">DB: {systemHealth?.database || 'SQLite'}</span>
        </div>

        {/* Action Button */}
        {location.pathname !== '/analyze' && (
          <Link
            to="/analyze"
            className="inline-flex items-center gap-1.5 rounded-md bg-accent px-3 py-1.5 text-xs font-semibold text-white shadow-sm hover:bg-accent-hover transition-all active:scale-[0.98]"
          >
            <Plus className="h-3.5 w-3.5" />
            <span>Analyze Threat</span>
          </Link>
        )}
      </div>
    </header>
  );
};
