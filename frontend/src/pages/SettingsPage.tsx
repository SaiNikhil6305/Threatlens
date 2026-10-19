import React, { useEffect, useState } from 'react';
import {
  Settings,
  Shield,
  Key,
  Database,
  RefreshCw,
  Trash2,
  CheckCircle2,
  XCircle,
  FileText,
  AlertTriangle,
  Activity,
  DownloadCloud
} from 'lucide-react';

import { api } from '../services/api';
import { LoadingSpinner } from '../components/LoadingSpinner';
import { ConfirmationModal } from '../components/ConfirmationModal';
import { useToast } from '../context/ToastContext';

export const SettingsPage: React.FC = () => {
  const { showToast } = useToast();
  const [settings, setSettings] = useState<any>(null);
  const [health, setHealth] = useState<any>(null);
  const [auditLogs, setAuditLogs] = useState<any[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  // Demo clear confirmation modal
  const [isClearModalOpen, setIsClearModalOpen] = useState(false);
  const [operatingDemo, setOperatingDemo] = useState(false);

  const fetchSettingsAndLogs = async () => {
    setLoading(true);
    setError(null);
    try {
      const [sData, hData, aData] = await Promise.all([
        api.getSettings(),
        api.getHealth(),
        api.getAuditLogs(),
      ]);
      setSettings(sData);
      setHealth(hData);
      setAuditLogs(aData);
    } catch (err: any) {
      setError(err.message || 'Failed to load system settings.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchSettingsAndLogs();
  }, []);

  const handleImportDemo = async () => {
    setOperatingDemo(true);
    setMessage(null);
    setError(null);
    showToast('Importing synthetic demonstration scenarios...', 'info');
    try {
      const res = await api.importDemoData();
      setMessage(res.message);
      showToast(res.message, 'success');
      await fetchSettingsAndLogs();
    } catch (err: any) {
      setError(err.message);
      showToast(err.message || 'Demo import failed.', 'error');
    } finally {
      setOperatingDemo(false);
    }
  };

  const handleClearDemo = async () => {
    setOperatingDemo(true);
    setMessage(null);
    setError(null);
    try {
      const res = await api.clearDemoData();
      setMessage(res.message);
      showToast(res.message, 'success');
      setIsClearModalOpen(false);
      await fetchSettingsAndLogs();
    } catch (err: any) {
      setError(err.message);
      showToast(err.message || 'Failed to clear demo data.', 'error');
    } finally {
      setOperatingDemo(false);
    }
  };

  if (loading && !settings) {
    return <LoadingSpinner message="Querying system settings & audit state..." />;
  }

  return (
    <div className="space-y-6">
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

      {/* External Intelligence Integrations */}
      <div className="rounded-lg bg-surface border border-border p-6 shadow-sm space-y-4">
        <div className="border-b border-border pb-3">
          <h2 className="text-sm font-semibold text-charcoal-900">External Threat Intelligence Integrations</h2>
          <p className="text-xs text-charcoal-500">
            Configure server-side API keys in <code className="font-mono text-accent">backend/.env</code> for optional live indicator enrichment.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
          {/* VirusTotal */}
          <div className="rounded-md border border-border p-4 bg-surface space-y-2">
            <div className="flex items-center justify-between">
              <span className="font-bold text-charcoal-900">VirusTotal v3 API</span>
              <span
                className={`inline-flex items-center gap-1 text-[11px] font-medium px-2 py-0.5 rounded border ${
                  settings?.virustotal_configured
                    ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
                    : 'bg-slate-50 text-slate-700 border-slate-200'
                }`}
              >
                {settings?.virustotal_configured ? 'Configured & Active' : 'Unconfigured (Offline Mode)'}
              </span>
            </div>
            <p className="text-charcoal-600 text-[11px]">
              Enriches IPv4 addresses, domains, and file hashes with multi-vendor AV detections.
            </p>
            <div className="text-[11px] font-mono text-charcoal-400">
              Key: {settings?.virustotal_configured ? '••••••••••••••••' : 'VIRUSTOTAL_API_KEY=""'}
            </div>
          </div>

          {/* AlienVault OTX */}
          <div className="rounded-md border border-border p-4 bg-surface space-y-2">
            <div className="flex items-center justify-between">
              <span className="font-bold text-charcoal-900">AlienVault OTX API</span>
              <span
                className={`inline-flex items-center gap-1 text-[11px] font-medium px-2 py-0.5 rounded border ${
                  settings?.alienvault_configured
                    ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
                    : 'bg-slate-50 text-slate-700 border-slate-200'
                }`}
              >
                {settings?.alienvault_configured ? 'Configured & Active' : 'Unconfigured (Offline Mode)'}
              </span>
            </div>
            <p className="text-charcoal-600 text-[11px]">
              Correlates indicators with AlienVault Open Threat Exchange community pulses.
            </p>
            <div className="text-[11px] font-mono text-charcoal-400">
              Key: {settings?.alienvault_configured ? '••••••••••••••••' : 'ALIENVAULT_OTX_API_KEY=""'}
            </div>
          </div>
        </div>
      </div>

      {/* Demonstration Dataset Management */}
      <div className="rounded-lg bg-surface border border-border p-6 shadow-sm space-y-4">
        <div className="border-b border-border pb-3">
          <h2 className="text-sm font-semibold text-charcoal-900">Demonstration Intelligence Dataset</h2>
          <p className="text-xs text-charcoal-500">
            Import or clear RFC 5737 compliant synthetic threat scenarios for testing without touching user submissions.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          <button
            type="button"
            disabled={operatingDemo}
            onClick={handleImportDemo}
            className="inline-flex items-center gap-1.5 rounded-md bg-navy-900 px-3.5 py-2 text-xs font-medium text-white shadow-sm hover:bg-navy-800 disabled:opacity-50 transition"
          >
            <DownloadCloud className="h-3.5 w-3.5" />
            <span>Import Demonstration Scenarios</span>
          </button>

          <button
            type="button"
            disabled={operatingDemo}
            onClick={() => setIsClearModalOpen(true)}
            className="inline-flex items-center gap-1.5 rounded-md border border-red-200 bg-red-50 px-3.5 py-2 text-xs font-medium text-red-700 hover:bg-red-100 disabled:opacity-50 transition"
          >
            <Trash2 className="h-3.5 w-3.5" />
            <span>Clear Demonstration Data</span>
          </button>
        </div>
      </div>

      {/* Database & Infrastructure Architecture */}
      <div className="rounded-lg bg-surface border border-border p-6 shadow-sm space-y-4">
        <div className="border-b border-border pb-3">
          <h2 className="text-sm font-semibold text-charcoal-900">Database & System Architecture</h2>
          <p className="text-xs text-charcoal-500">
            Operational runtime parameters and schema persistence information.
          </p>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 text-xs font-mono">
          <div className="rounded-md border border-border p-3 bg-surface-subtle">
            <span className="text-charcoal-400 block text-[10px] font-sans">Active Engine</span>
            <span className="font-bold text-charcoal-900 text-sm">SQLite 3</span>
            <span className="text-[10px] text-charcoal-500 block font-sans mt-0.5">PostgreSQL Migration Ready</span>
          </div>

          <div className="rounded-md border border-border p-3 bg-surface-subtle">
            <span className="text-charcoal-400 block text-[10px] font-sans">Max Input Narrative</span>
            <span className="font-bold text-charcoal-900 text-sm">{settings?.max_text_size_mb || 1} MB</span>
            <span className="text-[10px] text-charcoal-500 block font-sans mt-0.5">Standard Unicode text</span>
          </div>

          <div className="rounded-md border border-border p-3 bg-surface-subtle">
            <span className="text-charcoal-400 block text-[10px] font-sans">Max Upload Document</span>
            <span className="font-bold text-charcoal-900 text-sm">{settings?.max_file_size_mb || 10} MB</span>
            <span className="text-[10px] text-charcoal-500 block font-sans mt-0.5">TXT, CSV, JSON, PDF</span>
          </div>
        </div>
      </div>

      {/* Audit Events Trail */}
      <div className="rounded-lg bg-surface border border-border shadow-sm overflow-hidden">
        <div className="border-b border-border px-5 py-3.5">
          <h3 className="text-xs font-semibold text-charcoal-900 uppercase tracking-wider">
            System Audit Trail ({auditLogs.length} Events)
          </h3>
          <p className="text-xs text-charcoal-500">Records of investigations, model retraining, and triage updates</p>
        </div>

        <div className="overflow-x-auto max-h-60 overflow-y-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-surface-subtle text-charcoal-600 border-b border-border font-sans font-medium">
              <tr>
                <th className="px-5 py-2">Timestamp</th>
                <th className="px-5 py-2">Entity</th>
                <th className="px-5 py-2">Action</th>
                <th className="px-5 py-2">Details</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {auditLogs.map((log) => (
                <tr key={log.id} className="table-row-hover text-[11px]">
                  <td className="px-5 py-2 text-charcoal-500">
                    {new Date(log.created_at).toLocaleTimeString()}
                  </td>
                  <td className="px-5 py-2 font-bold text-charcoal-700">
                    {log.entity_type}
                  </td>
                  <td className="px-5 py-2 text-accent">
                    {log.action}
                  </td>
                  <td className="px-5 py-2 text-charcoal-800 font-sans truncate max-w-md">
                    {log.details}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Confirmation Modal */}
      <ConfirmationModal
        isOpen={isClearModalOpen}
        title="Clear Demonstration Scenarios"
        message="This action will remove all records created with source 'Demonstration Synthetic Feed'. Any investigations created manually or from user documents will be preserved."
        confirmText="Clear Demo Records"
        onConfirm={handleClearDemo}
        onCancel={() => setIsClearModalOpen(false)}
      />
    </div>
  );
};
