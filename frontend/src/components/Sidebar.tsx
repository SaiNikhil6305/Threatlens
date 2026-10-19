import React from 'react';
import { NavLink } from 'react-router-dom';
import {
  LayoutDashboard,
  Crosshair,
  Rss,
  Fingerprint,
  ShieldAlert,
  FileText,
  History,
  BarChart3,
  Settings,
  Shield,
  Activity,
  Layers,
  Sparkles
} from 'lucide-react';

interface SidebarProps {
  systemHealth?: {
    status: string;
    ml_model_loaded: boolean;
  };
}

export const Sidebar: React.FC<SidebarProps> = ({ systemHealth }) => {
  const navSections = [
    {
      group: 'TRIAGE & WORKBENCH',
      items: [
        { name: 'Overview', path: '/', icon: LayoutDashboard },
        { name: 'Analyze Threat', path: '/analyze', icon: Crosshair, highlight: true },
        { name: 'Analysis History', path: '/history', icon: History },
      ]
    },
    {
      group: 'THREAT INTELLIGENCE',
      items: [
        { name: 'Intelligence Feed', path: '/feed', icon: Rss },
        { name: 'Indicators (IoCs)', path: '/indicators', icon: Fingerprint },
        { name: 'MITRE ATT&CK', path: '/techniques', icon: ShieldAlert },
        { name: 'Intelligence Reports', path: '/reports', icon: FileText },
      ]
    },
    {
      group: 'MACHINE LEARNING & SYSTEM',
      items: [
        { name: 'Model Evaluation', path: '/model-evaluation', icon: BarChart3 },
        { name: 'Settings & Feeds', path: '/settings', icon: Settings },
      ]
    }
  ];

  return (
    <aside className="w-64 flex-shrink-0 flex flex-col bg-navy-900 border-r border-navy-800 select-none z-20 text-white shadow-sidebar">
      {/* Brand Header */}
      <div className="px-5 py-4 border-b border-navy-800 bg-navy-950/40">
        <div className="flex items-center gap-3">
          <div className="relative flex h-10 w-10 items-center justify-center rounded-lg bg-navy-800 border border-blue-400/30 shadow-md">
            {/* Cybersecurity Lens & Shield Emblem */}
            <Shield className="h-5 w-5 text-blue-400" />
            <span className="absolute -top-1 -right-1 flex h-2.5 w-2.5">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-blue-400 opacity-75" />
              <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-blue-400" />
            </span>
          </div>

          <div>
            <div className="flex items-center gap-1.5">
              <span className="font-bold text-base tracking-tight text-white">ThreatLens</span>
              <span className="text-[9px] font-mono font-semibold px-1 py-0.2 rounded bg-blue-500/20 text-blue-300 border border-blue-400/30">
                v1.0
              </span>
            </div>
            <p className="text-[10px] text-blue-200/70 font-medium leading-tight">
              Cyber Threat Intelligence Assistant
            </p>
          </div>
        </div>

        <div className="mt-2 text-[10px] text-blue-300/80 italic font-medium flex items-center gap-1">
          <span className="h-1 w-1 rounded-full bg-blue-400 inline-block" />
          <span>See Beyond the Threat.</span>
        </div>
      </div>

      {/* Navigation Groups */}
      <nav className="flex-1 px-3 py-3 space-y-4 overflow-y-auto">
        {navSections.map((sec, sIdx) => (
          <div key={sIdx} className="space-y-1">
            <div className="px-3 py-1 text-[10px] font-bold text-blue-300/50 uppercase tracking-wider">
              {sec.group}
            </div>
            {sec.items.map((item) => (
              <NavLink
                key={item.path}
                to={item.path}
                end={item.path === '/'}
                className={({ isActive }) =>
                  `group flex items-center justify-between px-3 py-2 text-xs font-medium rounded-md transition-all ${
                    isActive
                      ? 'bg-brand-blue text-white shadow-sm font-semibold border-l-4 border-white pl-2'
                      : 'text-slate-300 hover:text-white hover:bg-navy-800/70'
                  }`
                }
              >
                {({ isActive }) => (
                  <>
                    <div className="flex items-center gap-2.5">
                      <item.icon className={`h-4 w-4 flex-shrink-0 transition-colors ${
                        isActive ? 'text-white' : 'text-slate-400 group-hover:text-blue-300'
                      }`} />
                      <span>{item.name}</span>
                    </div>
                    {item.highlight && !isActive && (
                      <span className="flex h-1.5 w-1.5 rounded-full bg-blue-400" />
                    )}
                  </>
                )}
              </NavLink>
            ))}
          </div>
        ))}
      </nav>

      {/* Status Footer */}
      <div className="p-3.5 border-t border-navy-800 bg-navy-950/60">
        <div className="rounded-md border border-navy-800 bg-navy-900/90 p-2.5 space-y-1.5 shadow-inner">
          <div className="flex items-center justify-between text-xs">
            <span className="text-[11px] font-medium text-slate-300 flex items-center gap-1.5">
              <Activity className="h-3.5 w-3.5 text-blue-400" />
              Engine Status
            </span>
            <span className="inline-flex items-center gap-1 text-[10px] font-semibold text-emerald-300 bg-emerald-950/70 px-1.5 py-0.5 rounded border border-emerald-700/50">
              <span className="h-1.5 w-1.5 rounded-full bg-emerald-400 animate-pulse" />
              Operational
            </span>
          </div>
          <div className="text-[10px] text-slate-400 flex items-center justify-between font-mono pt-1 border-t border-navy-800">
            <span>ML Pipeline:</span>
            <span className="text-blue-300 font-semibold truncate max-w-[110px]">
              {systemHealth?.ml_model_loaded ? 'Active TF-IDF / SVM' : 'Rule Fallback'}
            </span>
          </div>
        </div>
      </div>
    </aside>
  );
};
