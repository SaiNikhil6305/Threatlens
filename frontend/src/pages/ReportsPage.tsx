import React, { useEffect, useState } from 'react';
import { useSearchParams, Link } from 'react-router-dom';
import {
  FileText,
  Download,
  Printer,
  Shield,
  AlertTriangle,
  CheckCircle2,
  ExternalLink,
  ChevronRight,
  Layers,
  ArrowLeft,
  Copy,
  Check,
  Share2
} from 'lucide-react';

import { api } from '../services/api';
import { AnalysisSummary } from '../types';
import { SeverityBadge } from '../components/SeverityBadge';
import { IndicatorBadge } from '../components/IndicatorBadge';
import { LoadingSpinner } from '../components/LoadingSpinner';
import { EmptyState } from '../components/EmptyState';
import { useToast } from '../context/ToastContext';

export const ReportsPage: React.FC = () => {
  const { showToast } = useToast();
  const [searchParams, setSearchParams] = useSearchParams();
  const reportIdParam = searchParams.get('id');

  const [analysesList, setAnalysesList] = useState<AnalysisSummary[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(reportIdParam);
  const [report, setReport] = useState<any | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [copiedSummary, setCopiedSummary] = useState(false);

  // Fetch list of investigations
  useEffect(() => {
    const fetchAnalyses = async () => {
      try {
        const list = await api.getAnalyses({ limit: 50 });
        setAnalysesList(list);
        if (!selectedId && list.length > 0) {
          setSelectedId(list[0].id);
        }
      } catch (err: any) {
        setError(err.message);
      }
    };
    fetchAnalyses();
  }, []);

  // Fetch report details whenever selectedId changes
  useEffect(() => {
    if (!selectedId) {
      setLoading(false);
      return;
    }
    const fetchReport = async () => {
      setLoading(true);
      setError(null);
      try {
        const data = await api.getReport(selectedId);
        setReport(data);
      } catch (err: any) {
        setError(err.message || 'Failed to generate report.');
      } finally {
        setLoading(false);
      }
    };
    fetchReport();
  }, [selectedId]);

  const handleSelectAnalysis = (id: string) => {
    setSelectedId(id);
    setSearchParams({ id });
  };

  const handlePrint = () => {
    window.print();
  };

  const handleCopySummary = () => {
    if (!report?.executive_summary) return;
    navigator.clipboard.writeText(report.executive_summary);
    setCopiedSummary(true);
    showToast('Executive Summary copied to clipboard', 'success');
    setTimeout(() => setCopiedSummary(false), 2000);
  };

  return (
    <div className="space-y-6">
      {/* Selector & Export Bar */}
      <div className="flex flex-wrap items-center justify-between gap-4 rounded-lg bg-surface p-4 border border-border shadow-sm print:hidden">
        <div className="flex items-center gap-3">
          <label className="text-xs font-semibold text-charcoal-700">Select Investigation:</label>
          <select
            value={selectedId || ''}
            onChange={(e) => handleSelectAnalysis(e.target.value)}
            className="rounded-md border border-border bg-surface px-3 py-1.5 text-xs text-charcoal-900 font-medium focus:outline-none focus:ring-1 focus:ring-accent max-w-xs sm:max-w-md truncate"
          >
            {analysesList.map((a) => (
              <option key={a.id} value={a.id}>
                {a.title} ({a.predicted_category} - {a.severity})
              </option>
            ))}
          </select>
        </div>

        {selectedId && report && (
          <div className="flex flex-wrap items-center gap-2">
            <button
              type="button"
              onClick={handlePrint}
              className="inline-flex items-center gap-1.5 rounded-md border border-border bg-surface px-3 py-1.5 text-xs font-medium text-charcoal-700 hover:bg-surface-subtle transition"
            >
              <Printer className="h-3.5 w-3.5" />
              <span>Print / PDF View</span>
            </button>

            <a
              href={api.exportReportUrl(selectedId, 'markdown')}
              download
              onClick={() => showToast('Downloading Markdown intelligence report...', 'info')}
              className="inline-flex items-center gap-1.5 rounded-md border border-border bg-surface px-3 py-1.5 text-xs font-medium text-charcoal-700 hover:bg-surface-subtle transition"
            >
              <Download className="h-3.5 w-3.5" />
              <span>Export Markdown</span>
            </a>

            <a
              href={api.exportReportUrl(selectedId, 'json')}
              download
              onClick={() => showToast('Downloading JSON intelligence report...', 'info')}
              className="inline-flex items-center gap-1.5 rounded-md bg-navy-900 px-3 py-1.5 text-xs font-medium text-white shadow-sm hover:bg-navy-800 transition"
            >
              <Download className="h-3.5 w-3.5" />
              <span>Export JSON</span>
            </a>
          </div>
        )}
      </div>

      {error && (
        <div className="rounded-md bg-red-50 border border-red-200 p-3.5 text-xs text-red-700">
          {error}
        </div>
      )}

      {loading ? (
        <LoadingSpinner message="Generating formal intelligence report..." />
      ) : !report ? (
        <EmptyState
          title="No Investigation Selected"
          description="Select an investigation report from the dropdown above or run a new analysis in the Threat Analysis Workspace."
        />
      ) : (
        /* Formal Intelligence Report Document */
        <article className="max-w-4xl mx-auto rounded-lg bg-surface border border-border shadow-sm p-8 sm:p-12 space-y-8 text-charcoal-900 font-sans print:shadow-none print:border-none print:p-0">
          {/* 1. Report Header */}
          <header className="border-b-2 border-charcoal-900 pb-6 space-y-3">
            <div className="flex items-center justify-between text-xs text-charcoal-500 font-mono">
              <span className="font-bold tracking-wider uppercase text-charcoal-900 flex items-center gap-2">
                <span className="px-1.5 py-0.5 rounded bg-amber-50 text-amber-700 border border-amber-200 text-[10px]">
                  TLP:AMBER
                </span>
                ThreatLens Cyber Threat Intelligence Assessment
              </span>
              <span className="text-[11px] font-mono text-charcoal-400">ID: {report.report_id}</span>
            </div>

            <h1 className="text-2xl font-bold tracking-tight text-charcoal-900">
              {report.title}
            </h1>

            <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 text-xs pt-2">
              <div>
                <span className="text-charcoal-400 block text-[10px] uppercase font-mono">Date / Time</span>
                <span className="font-medium">{new Date(report.created_at).toUTCString()}</span>
              </div>
              <div>
                <span className="text-charcoal-400 block text-[10px] uppercase font-mono">Originating Source</span>
                <span className="font-medium">{report.source}</span>
              </div>
              <div>
                <span className="text-charcoal-400 block text-[10px] uppercase font-mono">Investigation Status</span>
                <span className="font-medium text-emerald-700">{report.status}</span>
              </div>
              <div>
                <span className="text-charcoal-400 block text-[10px] uppercase font-mono">Triage Severity</span>
                <div className="mt-0.5">
                  <SeverityBadge severity={report.severity_assessment.severity} size="sm" />
                </div>
              </div>
            </div>
          </header>

          {/* 2. Executive Summary */}
          <section className="space-y-2">
            <div className="flex items-center justify-between border-b border-border pb-1">
              <h2 className="text-xs font-bold uppercase tracking-wider text-charcoal-500">
                1. Executive Summary
              </h2>
              <button
                type="button"
                onClick={handleCopySummary}
                className="inline-flex items-center gap-1 text-[11px] font-medium text-accent hover:text-accent-hover transition print:hidden"
              >
                {copiedSummary ? <Check className="h-3 w-3 text-emerald-600" /> : <Copy className="h-3 w-3" />}
                <span>{copiedSummary ? 'Copied' : 'Copy Summary'}</span>
              </button>
            </div>
            <p className="text-xs leading-relaxed text-charcoal-800 bg-surface-subtle/50 p-4 rounded border border-border font-medium">
              {report.executive_summary}
            </p>
          </section>

          {/* 3. Threat Classification */}
          <section className="space-y-3">
            <h2 className="text-xs font-bold uppercase tracking-wider text-charcoal-500 border-b border-border pb-1">
              2. Threat Classification & Methodology
            </h2>
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 text-xs p-3.5 rounded border border-border bg-surface">
              <div>
                <span className="text-charcoal-400 text-[10px] uppercase font-mono block">Classified Category</span>
                <span className="font-bold text-sm text-charcoal-900">{report.classification.category}</span>
              </div>
              <div>
                <span className="text-charcoal-400 text-[10px] uppercase font-mono block">Confidence Score</span>
                <span className="font-bold text-sm text-charcoal-900 font-mono">
                  {(report.classification.confidence * 100).toFixed(1)}%
                </span>
              </div>
              <div>
                <span className="text-charcoal-400 text-[10px] uppercase font-mono block">Inference Method</span>
                <span className="font-medium text-charcoal-800">{report.classification.prediction_method}</span>
              </div>
            </div>
            {report.classification.is_uncertain && (
              <div className="p-3 bg-amber-50 border border-amber-200 rounded text-xs text-amber-800">
                <strong>Analyst Notice:</strong> {report.classification.uncertainty_reason || 'Uncertainty threshold triggered during classification.'}
              </div>
            )}
          </section>

          {/* 4. Explainable Severity Assessment */}
          <section className="space-y-3">
            <h2 className="text-xs font-bold uppercase tracking-wider text-charcoal-500 border-b border-border pb-1">
              3. Severity Assessment & Heuristic Evaluation
            </h2>
            <div className="flex items-center justify-between text-xs p-3 rounded bg-surface-subtle border border-border">
              <span>Overall Assessed Severity: <strong>{report.severity_assessment.severity}</strong></span>
              <span className="font-mono">Heuristic Score: <strong>{report.severity_assessment.score} / 10.0</strong></span>
            </div>

            <div className="space-y-2">
              <h3 className="text-xs font-semibold text-charcoal-700">Triggered Rules:</h3>
              {report.severity_assessment.triggered_rules.map((r: any, idx: number) => (
                <div key={idx} className="flex items-start justify-between text-xs p-2 rounded border border-border bg-surface">
                  <div>
                    <span className="font-mono font-semibold text-charcoal-800">{r.rule}:</span>{' '}
                    <span className="text-charcoal-600">{r.description}</span>
                  </div>
                  <span className="font-mono text-accent font-bold ml-2">+{r.weight}</span>
                </div>
              ))}
            </div>
          </section>

          {/* 5. Indicators of Compromise */}
          <section className="space-y-3">
            <h2 className="text-xs font-bold uppercase tracking-wider text-charcoal-500 border-b border-border pb-1">
              4. Indicators of Compromise (IoCs) ({report.indicators.length})
            </h2>
            {report.indicators.length === 0 ? (
              <p className="text-xs text-charcoal-400 italic">No technical indicators extracted from submitted evidence.</p>
            ) : (
              <table className="w-full text-left text-xs border border-border divide-y divide-border rounded overflow-hidden">
                <thead className="bg-surface-subtle text-charcoal-600 font-medium">
                  <tr>
                    <th className="px-3 py-2">Indicator (Safe Defanged)</th>
                    <th className="px-3 py-2">Type</th>
                    <th className="px-3 py-2">Reputation</th>
                    <th className="px-3 py-2">Status</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {report.indicators.map((ind: any, idx: number) => (
                    <tr key={idx} className="table-row-hover">
                      <td className="px-3 py-2 font-mono font-medium text-charcoal-900">
                        {ind.defanged_value || ind.normalized_value}
                      </td>
                      <td className="px-3 py-2">
                        <IndicatorBadge type={ind.indicator_type} size="sm" />
                      </td>
                      <td className="px-3 py-2 text-charcoal-600">
                        {ind.reputation_status || 'Not checked'}
                      </td>
                      <td className="px-3 py-2 text-charcoal-500">
                        {ind.verification_status || 'Unverified'}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </section>

          {/* 6. Entities & Keywords */}
          <section className="space-y-3">
            <h2 className="text-xs font-bold uppercase tracking-wider text-charcoal-500 border-b border-border pb-1">
              5. Named Entities & Threat Actors
            </h2>
            {report.entities.length === 0 ? (
              <p className="text-xs text-charcoal-400 italic">No specific named entities recorded.</p>
            ) : (
              <div className="flex flex-wrap gap-2">
                {report.entities.map((e: any, idx: number) => (
                  <span
                    key={idx}
                    className="inline-flex items-center gap-1.5 rounded bg-surface-subtle px-2.5 py-1 text-xs text-charcoal-800 border border-border"
                  >
                    <span className="font-mono text-[10px] text-charcoal-400 uppercase">{e.entity_type}:</span>
                    <span className="font-medium">{e.entity_value}</span>
                  </span>
                ))}
              </div>
            )}
          </section>

          {/* 7. MITRE ATT&CK Mappings */}
          <section className="space-y-3">
            <h2 className="text-xs font-bold uppercase tracking-wider text-charcoal-500 border-b border-border pb-1">
              6. MITRE ATT&CK Framework Alignments
            </h2>
            {report.attack_techniques.length === 0 ? (
              <p className="text-xs text-charcoal-400 italic">No supported techniques mapped to available text narrative.</p>
            ) : (
              <div className="space-y-2">
                {report.attack_techniques.map((t: any, idx: number) => (
                  <div key={idx} className="p-3 rounded border border-border bg-surface text-xs space-y-1">
                    <div className="flex items-center justify-between font-mono">
                      <span className="font-bold text-accent">{t.technique_id} - {t.technique_name}</span>
                      <span className="text-[10px] text-charcoal-500 bg-surface-subtle px-2 py-0.5 rounded border border-border">
                        {t.tactic}
                      </span>
                    </div>
                    {t.evidence && (
                      <p className="font-mono text-[11px] text-charcoal-600 bg-surface-subtle p-1.5 rounded">
                        Evidence: {t.evidence}
                      </p>
                    )}
                  </div>
                ))}
              </div>
            )}
          </section>

          {/* 8. Defensive Recommendations */}
          <section className="space-y-3">
            <h2 className="text-xs font-bold uppercase tracking-wider text-charcoal-500 border-b border-border pb-1">
              7. Defensive Recommendations & Containment Playbook
            </h2>
            <div className="space-y-2">
              {report.defensive_recommendations.map((rec: any, idx: number) => (
                <div key={idx} className="p-3 rounded border border-border bg-surface-subtle/40 text-xs">
                  <div className="font-bold text-charcoal-900 mb-0.5">{rec.action}</div>
                  <div className="text-charcoal-600 leading-relaxed">{rec.detail}</div>
                </div>
              ))}
            </div>
          </section>

          {/* 9. Limitations & Caveats */}
          <section className="space-y-3">
            <h2 className="text-xs font-bold uppercase tracking-wider text-charcoal-500 border-b border-border pb-1">
              8. Investigation Limitations & Uncertainty Disclosures
            </h2>
            <ul className="list-disc list-inside text-xs text-charcoal-600 space-y-1.5">
              {report.limitations.map((lim: string, idx: number) => (
                <li key={idx}>{lim}</li>
              ))}
            </ul>
          </section>

          {/* Signoff */}
          <footer className="border-t border-border pt-6 text-[11px] text-charcoal-400 flex items-center justify-between font-mono">
            <span>ThreatLens Intelligence System • Generated via NLP & ML Pipeline</span>
            <span>Document Classification: TLP:AMBER</span>
          </footer>
        </article>
      )}
    </div>
  );
};
