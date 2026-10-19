import React, { useState } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import {
  FileText,
  Upload,
  Fingerprint,
  AlertTriangle,
  CheckCircle2,
  HelpCircle,
  Shield,
  Download,
  Share2,
  ExternalLink,
  Info,
  Layers,
  ArrowRight,
  Copy,
  Check,
  RotateCcw,
  Sparkles,
  Filter,
  CheckSquare,
  Square
} from 'lucide-react';

import { api } from '../services/api';
import { AnalysisResponse, IndicatorItem } from '../types';
import { SeverityBadge } from '../components/SeverityBadge';
import { IndicatorBadge } from '../components/IndicatorBadge';
import { LoadingSpinner } from '../components/LoadingSpinner';
import { EvidenceModal } from '../components/EvidenceModal';
import { useToast } from '../context/ToastContext';

const SAMPLE_PRESETS = [
  {
    tag: 'PHISHING',
    tagColor: 'bg-blue-50 text-blue-700 border-blue-200',
    name: 'Credential Harvester',
    title: 'Spearphishing Email with Credential Harvest Portal',
    source: 'SOC Incident Report',
    text: `Employees reported receiving spearphishing emails from accounting[at]payroll-portal.example[.]com urging immediate login verification at hxxps://secure-auth.corp-benefits.example[.]org/login.
The landing page harvests corporate credentials and drops an obfuscated payload with SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855.
External communication observed connecting to C2 IP 192.0.2.144 on port 8080.`
  },
  {
    tag: 'RANSOMWARE',
    tagColor: 'bg-red-50 text-red-700 border-red-200',
    name: 'LockBit Outbreak',
    title: 'LockBit Outbreak with Backup Shadow Copy Deletion',
    source: 'Threat Intelligence Bulletin',
    text: `Confirmed widespread active encryption of files across corporate workstations.
Ransomware operators executed 'vssadmin delete shadows /all /quiet' using PowerShell interpreter to eliminate volume backups.
Adversary dropped ransom note RESTORE-FILES.txt and initiated double extortion leak threats.
Beaconing observed to command and control IP 198.51.100.200 and hash MD5 44d88612fea8a8f36de82e1278abb02f.`
  },
  {
    tag: 'EXPLOITATION',
    tagColor: 'bg-orange-50 text-orange-700 border-orange-200',
    name: 'Log4Shell Edge Exploit',
    title: 'Active Log4j Exploitation on Edge Apache Solr',
    source: 'Vulnerability Advisory',
    text: `Unauthenticated remote code execution vulnerability in Apache Log4j (CVE-2021-44228) actively exploited in the wild.
Attacker IP 203.0.113.89 sent malicious JNDI LDAP lookup strings to public search endpoint.
Follow-on persistence established via web shell dropped on web server component.`
  },
  {
    tag: 'CRED DUMP',
    tagColor: 'bg-purple-50 text-purple-700 border-purple-200',
    name: 'Mimikatz Memory Harvest',
    title: 'Mimikatz Memory Dump and Kerberoasting Activity',
    source: 'EDR Alert',
    text: `Mimikatz executed on engineering host to perform credential dumping against LSASS process memory.
Adversaries dumped plaintext passwords and NTLM hashes, followed by Kerberoasting to extract service tickets for offline cracking.
Subsequent lateral movement observed via RDP to internal server 192.0.2.10.`
  },
  {
    tag: 'SAFE RUNBOOK',
    tagColor: 'bg-emerald-50 text-emerald-700 border-emerald-200',
    name: 'NIST IR Playbook',
    title: 'Corporate NIST SP 800-61 Incident Handling Procedure',
    source: 'Internal Governance Policy',
    text: `Enterprise Cyber Incident Response Standard Operating Procedure.
Framework: NIST SP 800-61 Rev. 2. Classification: Corporate Security Policy.
This document details incident triage SLAs, escalation procedures to the CISO, forensic order of volatility for volatile memory acquisition, and post-mortem review requirements.
Audited and verified under annual compliance audit protocols.`
  },
  {
    tag: 'SAFE SPEC',
    tagColor: 'bg-teal-50 text-teal-700 border-teal-200',
    name: 'Cloud K8s Spec',
    title: 'Enterprise Multi-Region Kubernetes Architecture',
    source: 'Architecture Blueprint',
    text: `Enterprise Cloud Hosting Blueprint: Multi-Region Kubernetes Deployment.
Classification: Corporate Security Policy and Compliance Audit Approved.
Architecture enforces Zero Trust Network Access (ZTNA), mutual TLS 1.3 service encryption, and ephemeral container workloads.
All telemetry is forwarded to internal monitoring dashboards with 99.99% availability.`
  }
];

export const AnalyzePage: React.FC = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const { showToast } = useToast();

  // Input tab: 'text' | 'document' | 'indicator'
  const [activeTab, setActiveTab] = useState<'text' | 'document' | 'indicator'>('text');

  // Form states
  const [title, setTitle] = useState('');
  const [source, setSource] = useState('Manual Submission');
  const [notes, setNotes] = useState('');
  const [textContent, setTextContent] = useState('');

  // Handle incoming state from feed or quick links
  React.useEffect(() => {
    if (location.state && (location.state as any).text) {
      const s = location.state as any;
      setTextContent(s.text || '');
      if (s.title) setTitle(s.title);
      if (s.source) setSource(s.source);
      setActiveTab('text');
      showToast('Loaded advisory into analysis workspace.', 'info');
    }
  }, [location.state]);

  // Document upload state
  const [file, setFile] = useState<File | null>(null);

  // Indicator lookup state
  const [indicatorInput, setIndicatorInput] = useState('');

  // Analysis result state
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<AnalysisResponse | null>(null);

  // IoC filtering & UI helpers
  const [iocTypeFilter, setIocTypeFilter] = useState<string>('All');
  const [copiedIndicator, setCopiedIndicator] = useState<string | null>(null);
  const [acknowledgedActions, setAcknowledgedActions] = useState<Set<number>>(new Set());

  // Evidence modal state
  const [selectedEvidence, setSelectedEvidence] = useState<{
    isOpen: boolean;
    title: string;
    indicatorValue?: string;
    indicatorType?: string;
    snippet?: string;
  }>({ isOpen: false, title: '' });

  const handleApplyPreset = (preset: typeof SAMPLE_PRESETS[0]) => {
    setActiveTab('text');
    setTitle(preset.title);
    setSource(preset.source);
    setTextContent(preset.text);
    setError(null);
    showToast(`Loaded "${preset.name}" into workspace.`, 'info');
  };

  const handleAnalyze = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);

    try {
      let res: AnalysisResponse;

      if (activeTab === 'text') {
        if (!textContent.trim()) {
          throw new Error('Please enter text content to analyze.');
        }
        res = await api.analyzeText(textContent, title, source, notes);
      } else if (activeTab === 'document') {
        if (!file) {
          throw new Error('Please select a document (TXT, CSV, JSON, PDF) to upload.');
        }
        res = await api.analyzeDocument(file, title, source, notes);
      } else {
        if (!indicatorInput.trim()) {
          throw new Error('Please enter an indicator value (IP, domain, URL, hash, CVE).');
        }
        res = await api.analyzeIndicator(indicatorInput, notes);
      }

      setResult(res);
      setAcknowledgedActions(new Set());
      setIocTypeFilter('All');
      showToast(`Threat analysis complete: ${res.severity} severity`, 'success');
    } catch (err: any) {
      setError(err.message || 'Threat analysis failed.');
      showToast(err.message || 'Threat analysis failed.', 'error');
    } finally {
      setLoading(false);
    }
  };



  const handleReset = () => {
    setResult(null);
    setTextContent('');
    setTitle('');
    setNotes('');
    setFile(null);
    setIndicatorInput('');
    setError(null);
    setAcknowledgedActions(new Set());
    showToast('Workspace reset.', 'info');
  };

  const handleCopyIndicator = (value: string) => {
    navigator.clipboard.writeText(value);
    setCopiedIndicator(value);
    showToast(`Copied indicator "${value}" to clipboard`, 'success');
    setTimeout(() => setCopiedIndicator(null), 2000);
  };

  const toggleAction = (index: number) => {
    setAcknowledgedActions((prev) => {
      const next = new Set(prev);
      if (next.has(index)) {
        next.delete(index);
      } else {
        next.add(index);
      }
      return next;
    });
  };

  // Metric counts for textarea
  const charCount = textContent.length;
  const wordCount = textContent.trim() ? textContent.trim().split(/\s+/).length : 0;
  const lineCount = textContent ? textContent.split('\n').length : 0;

  // Filtered indicators
  const filteredIndicators = result?.indicators.filter((ind) => {
    if (iocTypeFilter === 'All') return true;
    return ind.indicator_type.toLowerCase() === iocTypeFilter.toLowerCase();
  }) || [];

  return (
    <div className="space-y-6">
      {!result ? (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Main Input Form */}
          <div className="lg:col-span-2 rounded-lg bg-surface border border-border p-6 shadow-sm">
            <div className="flex flex-wrap items-center justify-between border-b border-border pb-4 mb-5 gap-3">
              <div>
                <h2 className="text-sm font-semibold text-charcoal-900">Investigation Input</h2>
                <p className="text-xs text-charcoal-500">Provide unstructured incident text, log dump, or technical indicator</p>
              </div>

              {/* Tabs */}
              <div className="inline-flex rounded-md bg-surface-subtle p-1 border border-border text-xs">
                <button
                  type="button"
                  onClick={() => { setActiveTab('text'); setError(null); }}
                  className={`flex items-center gap-1.5 px-3 py-1 rounded font-medium transition ${
                    activeTab === 'text' ? 'bg-surface text-charcoal-900 shadow-sm' : 'text-charcoal-500 hover:text-charcoal-800'
                  }`}
                >
                  <FileText className="h-3.5 w-3.5" />
                  <span>Analyze Text</span>
                </button>
                <button
                  type="button"
                  onClick={() => { setActiveTab('document'); setError(null); }}
                  className={`flex items-center gap-1.5 px-3 py-1 rounded font-medium transition ${
                    activeTab === 'document' ? 'bg-surface text-charcoal-900 shadow-sm' : 'text-charcoal-500 hover:text-charcoal-800'
                  }`}
                >
                  <Upload className="h-3.5 w-3.5" />
                  <span>Upload Document</span>
                </button>
                <button
                  type="button"
                  onClick={() => { setActiveTab('indicator'); setError(null); }}
                  className={`flex items-center gap-1.5 px-3 py-1 rounded font-medium transition ${
                    activeTab === 'indicator' ? 'bg-surface text-charcoal-900 shadow-sm' : 'text-charcoal-500 hover:text-charcoal-800'
                  }`}
                >
                  <Fingerprint className="h-3.5 w-3.5" />
                  <span>Analyze Indicator</span>
                </button>
              </div>
            </div>

            {error && (
              <div className="rounded-md bg-red-50 border border-red-200 p-3.5 text-xs text-red-700 mb-5 flex items-start gap-2">
                <AlertTriangle className="h-4 w-4 text-red-600 flex-shrink-0 mt-0.5" />
                <span>{error}</span>
              </div>
            )}

            <form onSubmit={handleAnalyze} className="space-y-4">
              {activeTab !== 'indicator' && (
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                  <div>
                    <label className="block text-xs font-medium text-charcoal-700 mb-1">
                      Investigation Title (Optional)
                    </label>
                    <input
                      type="text"
                      placeholder="e.g. Finance Spearphishing Incident 2026-Q4"
                      value={title}
                      onChange={(e) => setTitle(e.target.value)}
                      className="w-full rounded-md border border-border bg-surface px-3 py-2 text-xs text-charcoal-900 placeholder-charcoal-400 focus:outline-none focus:ring-1 focus:ring-accent"
                    />
                  </div>

                  <div>
                    <label className="block text-xs font-medium text-charcoal-700 mb-1">
                      Originating Source
                    </label>
                    <input
                      type="text"
                      placeholder="e.g. Email Gateway, EDR, Incident Ticket"
                      value={source}
                      onChange={(e) => setSource(e.target.value)}
                      className="w-full rounded-md border border-border bg-surface px-3 py-2 text-xs text-charcoal-900 placeholder-charcoal-400 focus:outline-none focus:ring-1 focus:ring-accent"
                    />
                  </div>
                </div>
              )}

              {/* Tab 1: Text */}
              {activeTab === 'text' && (
                <div>
                  <div className="flex items-center justify-between mb-1">
                    <label className="block text-xs font-medium text-charcoal-700">
                      Threat Narrative, Security Advisory, or Log Excerpt <span className="text-red-500">*</span>
                    </label>
                    <div className="flex items-center gap-2 text-[10px] font-mono text-charcoal-400">
                      <span>{charCount} chars</span>
                      <span>•</span>
                      <span>{wordCount} words</span>
                      <span>•</span>
                      <span>{lineCount} lines</span>
                    </div>
                  </div>
                  <textarea
                    rows={8}
                    required
                    placeholder="Paste email content, CTI bulletin, malware analysis notes, or raw IOC evidence here..."
                    value={textContent}
                    onChange={(e) => setTextContent(e.target.value)}
                    className="w-full font-mono text-xs rounded-md border border-border bg-surface p-3 text-charcoal-900 placeholder-charcoal-400 focus:outline-none focus:ring-1 focus:ring-accent shadow-2xs leading-relaxed"
                  />
                  <div className="flex items-center justify-between text-[11px] text-charcoal-400 mt-1">
                    <span>Accepts standard & defanged tokens (<code className="font-mono text-accent">hxxp://</code>, <code className="font-mono text-accent">[.]</code>, <code className="font-mono text-accent">[at]</code>). Tokens refanged for normalization.</span>
                  </div>
                </div>
              )}

              {/* Tab 2: Document */}
              {activeTab === 'document' && (
                <div className="space-y-4">
                  <div>
                    <label className="block text-xs font-medium text-charcoal-700 mb-1">
                      Select Threat Document (PDF, TXT, CSV, JSON) <span className="text-red-500">*</span>
                    </label>
                    <div className="flex flex-col items-center justify-center rounded-lg border-2 border-dashed border-border p-8 bg-surface-subtle/50 text-center hover:bg-surface-subtle/80 transition">
                      <div className="flex h-12 w-12 items-center justify-center rounded-full bg-accent/10 text-accent mb-3">
                        <Upload className="h-6 w-6" />
                      </div>
                      <p className="text-sm text-charcoal-800 font-semibold mb-1">
                        {file ? file.name : 'Select or drop a test document'}
                      </p>
                      <p className="text-xs text-charcoal-500 max-w-md mb-4">
                        Choose any test PDF from your local <code className="font-mono text-accent bg-accent/10 px-1.5 py-0.5 rounded text-[11px]">sample_documents/</code> folder (up to 10 MB)
                      </p>
                      
                      {file ? (
                        <div className="flex items-center gap-3 bg-surface border border-border px-3.5 py-2 rounded-md shadow-2xs">
                          <FileText className="h-4 w-4 text-accent" />
                          <div className="text-left">
                            <p className="text-xs font-medium text-charcoal-800">{file.name}</p>
                            <p className="text-[10px] text-charcoal-400">{(file.size / 1024).toFixed(1)} KB</p>
                          </div>
                          <button
                            type="button"
                            onClick={() => setFile(null)}
                            className="ml-2 text-xs text-red-500 hover:text-red-700 underline font-medium"
                          >
                            Remove
                          </button>
                        </div>
                      ) : (
                        <label className="cursor-pointer">
                          <span className="inline-flex items-center gap-2 rounded-md bg-accent px-4 py-2 text-xs font-medium text-white shadow-2xs hover:bg-accent-hover transition">
                            <Upload className="h-3.5 w-3.5" /> Browse Local Documents
                          </span>
                          <input
                            type="file"
                            accept=".pdf,.txt,.csv,.json"
                            onChange={(e) => {
                              if (e.target.files && e.target.files[0]) {
                                const selected = e.target.files[0];
                                setFile(selected);
                                if (!title) {
                                  setTitle(selected.name.replace(/\.[^/.]+$/, '').replace(/_/g, ' '));
                                }
                              }
                            }}
                            className="hidden"
                          />
                        </label>
                      )}
                    </div>
                  </div>

                  <div className="flex items-center justify-between p-3 rounded-md border border-border bg-surface text-xs text-charcoal-600">
                    <div className="flex items-center gap-2">
                      <Info className="h-4 w-4 text-accent flex-shrink-0" />
                      <span>
                        All 20 test documents (10 Threat & 10 Safe) are saved as PDFs in <code className="font-mono text-charcoal-800 bg-surface-subtle px-1.5 py-0.5 rounded">sample_documents/</code>.
                      </span>
                    </div>
                  </div>
                </div>
              )}

              {/* Tab 3: Indicator */}
              {activeTab === 'indicator' && (
                <div>
                  <label className="block text-xs font-medium text-charcoal-700 mb-1">
                    Technical Indicator <span className="text-red-500">*</span>
                  </label>
                  <input
                    type="text"
                    required
                    placeholder="e.g. 198.51.100.77, bad-domain.com, CVE-2021-44228, or file hash"
                    value={indicatorInput}
                    onChange={(e) => setIndicatorInput(e.target.value)}
                    className="w-full font-mono rounded-md border border-border bg-surface px-3 py-2 text-xs text-charcoal-900 placeholder-charcoal-400 focus:outline-none focus:ring-1 focus:ring-accent"
                  />
                  <p className="text-[11px] text-charcoal-400 mt-1">
                    Accepts IPv4, domain, URL, MD5, SHA-1, SHA-256, email, or CVE identifier.
                  </p>
                </div>
              )}

              <div>
                <label className="block text-xs font-medium text-charcoal-700 mb-1">
                  Analyst Triage Notes (Optional)
                </label>
                <input
                  type="text"
                  placeholder="e.g. Forwarded from tier-1 queue for investigation"
                  value={notes}
                  onChange={(e) => setNotes(e.target.value)}
                  className="w-full rounded-md border border-border bg-surface px-3 py-2 text-xs text-charcoal-900 placeholder-charcoal-400 focus:outline-none focus:ring-1 focus:ring-accent"
                />
              </div>

              <div className="flex items-center justify-between pt-3 border-t border-border">
                <button
                  type="button"
                  onClick={handleReset}
                  className="inline-flex items-center gap-1.5 rounded-md border border-border bg-surface px-3 py-1.5 text-xs font-medium text-charcoal-600 hover:bg-surface-subtle transition"
                >
                  <RotateCcw className="h-3 w-3" />
                  <span>Clear Fields</span>
                </button>
                <button
                  type="submit"
                  disabled={loading}
                  className="inline-flex items-center gap-2 rounded-md bg-navy-900 px-5 py-2 text-xs font-semibold text-white shadow-sm hover:bg-navy-800 disabled:opacity-50 transition active:scale-[0.98]"
                >
                  {loading ? (
                    <>
                      <span className="h-3.5 w-3.5 border-2 border-white/20 border-t-white rounded-full animate-spin" />
                      <span>Running NLP & ML Pipeline...</span>
                    </>
                  ) : (
                    <>
                      <Sparkles className="h-3.5 w-3.5 text-accent" />
                      <span>Analyze Threat</span>
                    </>
                  )}
                </button>
              </div>
            </form>
          </div>

          {/* Quick Presets Side Panel */}
          <div className="space-y-4">
            <div className="rounded-lg bg-surface border border-border p-5 shadow-sm">
              <div className="flex items-center justify-between mb-2">
                <h3 className="text-xs font-bold text-charcoal-900 uppercase tracking-wider">
                  Sample Scenarios
                </h3>
                <span className="text-[10px] text-accent font-semibold">1-Click Load</span>
              </div>
              <p className="text-xs text-charcoal-500 mb-3">
                Load curated technical threat reports for instant testing & evaluation:
              </p>

              <div className="space-y-2">
                {SAMPLE_PRESETS.map((preset, idx) => (
                  <button
                    key={idx}
                    type="button"
                    onClick={() => handleApplyPreset(preset)}
                    className="w-full text-left p-3 rounded-md border border-border bg-surface hover:bg-surface-subtle transition text-xs group interactive-card"
                  >
                    <div className="flex items-center justify-between mb-1">
                      <span className="font-semibold text-charcoal-900 group-hover:text-accent transition-colors">
                        {preset.name}
                      </span>
                      <span className={`text-[9px] font-mono px-1.5 py-0.5 rounded border font-semibold ${preset.tagColor}`}>
                        {preset.tag}
                      </span>
                    </div>
                    <div className="text-[11px] text-charcoal-500 truncate">
                      {preset.title}
                    </div>
                  </button>
                ))}
              </div>
            </div>

            <div className="rounded-lg bg-surface border border-border p-5 shadow-sm">
              <h3 className="text-xs font-bold text-charcoal-900 uppercase tracking-wider mb-2">
                Processing Guarantee
              </h3>
              <ul className="text-xs text-charcoal-600 space-y-2.5">
                <li className="flex items-start gap-2">
                  <CheckCircle2 className="h-3.5 w-3.5 text-emerald-600 mt-0.5 flex-shrink-0" />
                  <span><strong>Defanged token refanging:</strong> IPv4, domain, URL, CVE, email normalization</span>
                </li>
                <li className="flex items-start gap-2">
                  <CheckCircle2 className="h-3.5 w-3.5 text-emerald-600 mt-0.5 flex-shrink-0" />
                  <span><strong>Supervised ML text classifier:</strong> TF-IDF + Logistic Regression / SVM</span>
                </li>
                <li className="flex items-start gap-2">
                  <CheckCircle2 className="h-3.5 w-3.5 text-emerald-600 mt-0.5 flex-shrink-0" />
                  <span><strong>Explainable severity assessment:</strong> Heuristic rule scoring & missing context</span>
                </li>
                <li className="flex items-start gap-2">
                  <CheckCircle2 className="h-3.5 w-3.5 text-emerald-600 mt-0.5 flex-shrink-0" />
                  <span><strong>MITRE ATT&CK correlation:</strong> Automated technique mapping & evidence snippets</span>
                </li>
              </ul>
            </div>
          </div>
        </div>
      ) : (
        /* Results View */
        <div className="space-y-6">
          {/* Action Header Banner */}
          <div className="flex flex-wrap items-center justify-between gap-4 rounded-lg bg-surface p-5 border border-border shadow-sm">
            <div>
              <div className="flex items-center gap-2 mb-1.5">
                <h2 className="text-base font-bold text-charcoal-900 tracking-tight">{result.title}</h2>
                <SeverityBadge severity={result.severity} size="md" />
              </div>
              <div className="flex flex-wrap items-center gap-3 text-xs text-charcoal-500">
                <span>Category: <strong className="text-charcoal-800">{result.predicted_category}</strong></span>
                <span>•</span>
                <span>Confidence: <strong className="text-charcoal-800">{(result.confidence * 100).toFixed(1)}%</strong></span>
                <span>•</span>
                <span>Method: <strong className="text-charcoal-800">{result.prediction_method}</strong></span>
                <span>•</span>
                <span className="font-mono text-[11px] text-charcoal-400">ID: {result.id.slice(0, 8)}</span>
              </div>
            </div>

            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={handleReset}
                className="inline-flex items-center gap-1.5 rounded-md border border-border bg-surface px-3 py-1.5 text-xs font-medium text-charcoal-700 hover:bg-surface-subtle transition"
              >
                <RotateCcw className="h-3.5 w-3.5" />
                <span>New Analysis</span>
              </button>
              <button
                type="button"
                onClick={() => navigate(`/reports?id=${result.id}`)}
                className="inline-flex items-center gap-1.5 rounded-md bg-navy-900 px-3.5 py-1.5 text-xs font-semibold text-white shadow-sm hover:bg-navy-800 transition active:scale-[0.98]"
              >
                <FileText className="h-3.5 w-3.5" />
                <span>View Full Report</span>
              </button>
            </div>
          </div>

          {/* Uncertainty Warning Banner */}
          {result.is_uncertain && (
            <div className="rounded-md bg-amber-50 border border-amber-200 p-4 text-xs text-amber-800 flex items-start gap-2.5">
              <AlertTriangle className="h-4 w-4 text-amber-600 flex-shrink-0 mt-0.5" />
              <div>
                <strong>High Uncertainty Flag:</strong> The classifier indicated lower statistical confidence or ambiguous signals.
                Treat this categorization as a triage hypothesis requiring analyst verification.
              </div>
            </div>
          )}

          {/* Visual Severity Meter Card */}
          <div className="rounded-lg bg-surface border border-border p-5 shadow-sm space-y-3">
            <div className="flex items-center justify-between">
              <div>
                <h3 className="text-xs font-bold text-charcoal-900 uppercase tracking-wider">
                  Severity Score Meter
                </h3>
                <p className="text-[11px] text-charcoal-500">
                  Calibrated scale based on asset criticality, active exploit, and data loss impact
                </p>
              </div>
              <div className="text-right">
                <span className="text-2xl font-bold font-mono tracking-tight text-charcoal-900">
                  {result.severity_score.toFixed(1)}
                </span>
                <span className="text-xs text-charcoal-400 font-mono"> / 10.0</span>
              </div>
            </div>

            {/* Gauge track */}
            <div className="relative pt-2 pb-1">
              <div className="h-3 w-full bg-surface-subtle rounded-full overflow-hidden border border-border flex">
                <div className="h-full bg-emerald-500" style={{ width: '39%' }} title="Low: 0.0 - 3.9" />
                <div className="h-full bg-amber-500" style={{ width: '30%' }} title="Medium: 4.0 - 6.9" />
                <div className="h-full bg-orange-500" style={{ width: '20%' }} title="High: 7.0 - 8.9" />
                <div className="h-full bg-red-600" style={{ width: '11%' }} title="Critical: 9.0 - 10.0" />
              </div>

              {/* Needle cursor */}
              <div
                className="absolute top-1 transform -translate-x-1/2 flex flex-col items-center pointer-events-none transition-all duration-500"
                style={{ left: `${Math.min(Math.max((result.severity_score / 10) * 100, 2), 98)}%` }}
              >
                <div className="h-5 w-2 rounded-full bg-navy-900 ring-2 ring-white shadow-lg" />
              </div>
            </div>

            <div className="flex items-center justify-between text-[10px] font-mono text-charcoal-400">
              <span className="text-emerald-700 font-medium">Low (0.0 - 3.9)</span>
              <span className="text-amber-700 font-medium">Medium (4.0 - 6.9)</span>
              <span className="text-orange-700 font-medium">High (7.0 - 8.9)</span>
              <span className="text-red-700 font-medium">Critical (9.0 - 10.0)</span>
            </div>
          </div>

          {/* Grid Layout for Severity Rationale & IOCs */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Left 2 Cols: Indicators & Techniques */}
            <div className="lg:col-span-2 space-y-6">
              {/* Extracted Indicators Table */}
              <div className="rounded-lg bg-surface border border-border shadow-sm overflow-hidden">
                <div className="border-b border-border px-5 py-3.5 flex flex-wrap items-center justify-between gap-2">
                  <div>
                    <h3 className="text-xs font-bold text-charcoal-900 uppercase tracking-wider">
                      Extracted Indicators of Compromise ({result.indicators.length})
                    </h3>
                    <p className="text-[11px] text-charcoal-500">Defanged technical tokens with evidence snippets & quick copy</p>
                  </div>

                  {/* Filter Pills */}
                  {result.indicators.length > 0 && (
                    <div className="flex items-center gap-1 text-[11px]">
                      {['All', 'ipv4', 'domain', 'url', 'sha256', 'cve'].map((typeKey) => {
                        const count = typeKey === 'All'
                          ? result.indicators.length
                          : result.indicators.filter((i) => i.indicator_type.toLowerCase() === typeKey).length;
                        if (count === 0 && typeKey !== 'All') return null;

                        return (
                          <button
                            key={typeKey}
                            type="button"
                            onClick={() => setIocTypeFilter(typeKey)}
                            className={`px-2 py-0.5 rounded font-mono transition text-[10px] ${
                              iocTypeFilter.toLowerCase() === typeKey.toLowerCase()
                                ? 'bg-navy-900 text-white font-semibold'
                                : 'bg-surface-subtle text-charcoal-600 hover:bg-border'
                            }`}
                          >
                            {typeKey.toUpperCase()} ({count})
                          </button>
                        );
                      })}
                    </div>
                  )}
                </div>

                {result.indicators.length === 0 ? (
                  <div className="p-8 text-center text-xs text-charcoal-400">
                    No technical indicators (IPs, domains, hashes, CVEs) were detected in this narrative.
                  </div>
                ) : filteredIndicators.length === 0 ? (
                  <div className="p-8 text-center text-xs text-charcoal-400">
                    No indicators match the selected filter pill.
                  </div>
                ) : (
                  <div className="overflow-x-auto">
                    <table className="w-full text-left text-xs">
                      <thead className="bg-surface-subtle text-charcoal-600 border-b border-border font-medium">
                        <tr>
                          <th className="px-5 py-2.5">Indicator (Defanged)</th>
                          <th className="px-5 py-2.5">Type</th>
                          <th className="px-5 py-2.5">Reputation</th>
                          <th className="px-5 py-2.5">Status</th>
                          <th className="px-5 py-2.5 text-right">Action</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-border">
                        {filteredIndicators.map((ind, i) => {
                          const displayVal = ind.defanged_value || ind.normalized_value;
                          const isCopied = copiedIndicator === displayVal;

                          return (
                            <tr key={i} className="table-row-hover">
                              <td className="px-5 py-2.5 font-mono font-medium text-charcoal-900">
                                <div className="flex items-center gap-2">
                                  <span>{displayVal}</span>
                                  <button
                                    type="button"
                                    onClick={() => handleCopyIndicator(displayVal)}
                                    className="p-1 text-charcoal-400 hover:text-charcoal-800 transition rounded hover:bg-surface-subtle"
                                    title="Copy defanged indicator"
                                  >
                                    {isCopied ? (
                                      <Check className="h-3 w-3 text-emerald-600" />
                                    ) : (
                                      <Copy className="h-3 w-3" />
                                    )}
                                  </button>
                                </div>
                              </td>
                              <td className="px-5 py-2.5">
                                <IndicatorBadge type={ind.indicator_type} size="sm" />
                              </td>
                              <td className="px-5 py-2.5 text-charcoal-600">
                                {ind.reputation_status || 'Not checked'}
                              </td>
                              <td className="px-5 py-2.5 text-charcoal-500">
                                {ind.verification_status || 'Unverified'}
                              </td>
                              <td className="px-5 py-2.5 text-right">
                                <button
                                  type="button"
                                  onClick={() => setSelectedEvidence({
                                    isOpen: true,
                                    title: 'Indicator Evidence Snippet',
                                    indicatorValue: displayVal,
                                    indicatorType: ind.indicator_type,
                                    snippet: ind.evidence_snippet
                                  })}
                                  className="text-accent hover:text-accent-hover font-medium"
                                >
                                  View Snippet
                                </button>
                              </td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>

              {/* MITRE ATT&CK Mappings */}
              <div className="rounded-lg bg-surface border border-border p-5 shadow-sm">
                <div className="mb-4">
                  <h3 className="text-xs font-bold text-charcoal-900 uppercase tracking-wider">
                    MITRE ATT&CK Technique Mappings ({result.techniques.length})
                  </h3>
                  <p className="text-[11px] text-charcoal-500">Correlated tactics & verified technique identifiers</p>
                </div>

                {result.techniques.length === 0 ? (
                  <p className="text-xs text-charcoal-400 italic">
                    No contextual technique mappings identified for this narrative.
                  </p>
                ) : (
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                    {result.techniques.map((t, idx) => (
                      <div key={idx} className="rounded-md border border-border p-3 bg-surface-subtle/50 text-xs interactive-card">
                        <div className="flex items-center justify-between mb-1">
                          <span className="font-mono font-bold text-accent">{t.technique_id}</span>
                          <span className="rounded bg-navy-900/10 text-navy-900 px-1.5 py-0.5 text-[10px] font-medium">
                            {t.tactic}
                          </span>
                        </div>
                        <div className="font-semibold text-charcoal-900 mb-1">{t.technique_name}</div>
                        {t.evidence && (
                          <p className="font-mono text-[11px] text-charcoal-600 line-clamp-2 bg-surface p-1.5 rounded border border-border">
                            {t.evidence}
                          </p>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* Defensive Containment Checklist */}
              <div className="rounded-lg bg-surface border border-border p-5 shadow-sm space-y-3">
                <div className="flex items-center justify-between">
                  <div>
                    <h3 className="text-xs font-bold text-charcoal-900 uppercase tracking-wider">
                      Containment & Response Playbook
                    </h3>
                    <p className="text-[11px] text-charcoal-500">
                      Interactive triage checklist for security operations
                    </p>
                  </div>
                  <div className="text-right">
                    <span className="text-[11px] font-semibold text-charcoal-700">
                      {acknowledgedActions.size} of {result.defensive_recommendations.length} complete
                    </span>
                  </div>
                </div>

                {/* Progress bar */}
                <div className="h-1.5 w-full bg-surface-subtle rounded-full overflow-hidden border border-border">
                  <div
                    className="h-full bg-accent transition-all duration-300 rounded-full"
                    style={{
                      width: `${
                        result.defensive_recommendations.length > 0
                          ? (acknowledgedActions.size / result.defensive_recommendations.length) * 100
                          : 0
                      }%`
                    }}
                  />
                </div>

                <div className="space-y-2 pt-1">
                  {result.defensive_recommendations.map((rec, idx) => {
                    const isDone = acknowledgedActions.has(idx);
                    return (
                      <div
                        key={idx}
                        onClick={() => toggleAction(idx)}
                        className={`flex items-start gap-3 p-3 rounded-md border cursor-pointer transition text-xs select-none ${
                          isDone
                            ? 'bg-emerald-50/50 border-emerald-200 text-charcoal-500'
                            : 'bg-surface border-border text-charcoal-800 hover:bg-surface-subtle'
                        }`}
                      >
                        <div className="mt-0.5 flex-shrink-0">
                          {isDone ? (
                            <CheckCircle2 className="h-4 w-4 text-emerald-600" />
                          ) : (
                            <div className="h-4 w-4 rounded border border-charcoal-300 hover:border-accent" />
                          )}
                        </div>
                        <div className="flex-1">
                          <span className={`font-semibold ${isDone ? 'line-through text-charcoal-500' : 'text-charcoal-900'}`}>
                            {rec.action}:
                          </span>{' '}
                          <span className={isDone ? 'line-through text-charcoal-400' : 'text-charcoal-700'}>
                            {rec.detail}
                          </span>
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>
            </div>

            {/* Right 1 Col: Severity Rationale & Missing Info */}
            <div className="space-y-6">
              {/* Severity Rationale Breakdown */}
              <div className="rounded-lg bg-surface border border-border p-5 shadow-sm space-y-4">
                <div>
                  <h3 className="text-xs font-bold text-charcoal-900 uppercase tracking-wider">
                    Explainable Rationale
                  </h3>
                  <p className="text-[11px] text-charcoal-500">Heuristic rule weight evaluations</p>
                </div>

                <div>
                  <h4 className="text-xs font-semibold text-charcoal-800 mb-2">Triggered Rules:</h4>
                  <div className="space-y-2">
                    {result.severity_rationale?.triggered_rules?.length === 0 ? (
                      <p className="text-xs text-charcoal-400">Baseline scoring only.</p>
                    ) : (
                      result.severity_rationale?.triggered_rules?.map((rule, idx) => (
                        <div key={idx} className="p-2.5 rounded border border-border bg-surface text-xs">
                          <div className="flex items-center justify-between font-mono text-[11px] text-charcoal-700 font-semibold mb-0.5">
                            <span>{rule.rule}</span>
                            <span className="text-accent">+{rule.weight}</span>
                          </div>
                          <p className="text-[11px] text-charcoal-500">{rule.description}</p>
                        </div>
                      ))
                    )}
                  </div>
                </div>

                {/* Missing Context */}
                {result.severity_rationale?.missing_information?.length > 0 && (
                  <div>
                    <h4 className="text-xs font-semibold text-charcoal-800 mb-2">Missing Context / Uncertainties:</h4>
                    <ul className="list-disc list-inside text-xs text-charcoal-600 space-y-1">
                      {result.severity_rationale.missing_information.map((item, idx) => (
                        <li key={idx} className="text-[11px] text-amber-900">{item}</li>
                      ))}
                    </ul>
                  </div>
                )}

                <div className="text-[11px] text-charcoal-400 italic pt-2 border-t border-border">
                  {result.severity_rationale?.assessment_disclaimer}
                </div>
              </div>

              {/* Extracted Entities */}
              <div className="rounded-lg bg-surface border border-border p-5 shadow-sm">
                <h3 className="text-xs font-bold text-charcoal-900 uppercase tracking-wider mb-2">
                  Extracted Entities & Actors ({result.entities.length})
                </h3>
                {result.entities.length === 0 ? (
                  <p className="text-xs text-charcoal-400 italic">No specific named entities identified.</p>
                ) : (
                  <div className="flex flex-wrap gap-1.5">
                    {result.entities.map((e, idx) => (
                      <span
                        key={idx}
                        className="inline-flex items-center gap-1 rounded bg-surface-subtle px-2 py-1 text-[11px] font-medium text-charcoal-800 border border-border"
                      >
                        <span className="text-[10px] text-charcoal-400 uppercase font-mono">{e.entity_type}:</span>
                        <span>{e.entity_value}</span>
                      </span>
                    ))}
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Evidence Modal */}
      <EvidenceModal
        isOpen={selectedEvidence.isOpen}
        title={selectedEvidence.title}
        indicatorValue={selectedEvidence.indicatorValue}
        indicatorType={selectedEvidence.indicatorType}
        snippet={selectedEvidence.snippet}
        onClose={() => setSelectedEvidence({ ...selectedEvidence, isOpen: false })}
      />
    </div>
  );
};
