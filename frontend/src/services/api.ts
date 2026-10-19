import {
  AnalysisResponse,
  AnalysisSummary,
  DashboardSummaryData,
  IndicatorDetail,
  AttackTechniqueRef,
  IntelligenceFeedItem,
  ModelEvaluationData,
  SystemHealth
} from '../types';

const API_BASE = '/api';

export async function handleResponse<T>(res: Response): Promise<T> {
  if (!res.ok) {
    let errMsg = `Request failed with status ${res.status}`;
    try {
      const errData = await res.json();
      if (errData.detail) errMsg = errData.detail;
    } catch {
      // ignore
    }
    throw new Error(errMsg);
  }
  return res.json() as Promise<T>;
}

export const api = {
  // --- Analysis ---
  analyzeText: (text: string, title?: string, source?: string, notes?: string) =>
    fetch(`${API_BASE}/analyze/text`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text, title, source, notes }),
    }).then(handleResponse<AnalysisResponse>),

  analyzeDocument: (file: File, title?: string, source?: string, notes?: string) => {
    const formData = new FormData();
    formData.append('file', file);
    if (title) formData.append('title', title);
    if (source) formData.append('source', source);
    if (notes) formData.append('notes', notes);
    return fetch(`${API_BASE}/analyze/document`, {
      method: 'POST',
      body: formData,
    }).then(handleResponse<AnalysisResponse>);
  },

  analyzeIndicator: (indicator: string, notes?: string) =>
    fetch(`${API_BASE}/analyze/indicator`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ indicator, notes }),
    }).then(handleResponse<AnalysisResponse>),

  getAnalyses: (params?: { q?: string; category?: string; severity?: string; status?: string; skip?: number; limit?: number }) => {
    const query = new URLSearchParams();
    if (params?.q) query.append('q', params.q);
    if (params?.category) query.append('category', params.category);
    if (params?.severity) query.append('severity', params.severity);
    if (params?.status) query.append('status', params.status);
    if (params?.skip !== undefined) query.append('skip', String(params.skip));
    if (params?.limit !== undefined) query.append('limit', String(params.limit));
    return fetch(`${API_BASE}/analyses?${query.toString()}`).then(handleResponse<AnalysisSummary[]>);
  },

  getAnalysisDetail: (id: string) =>
    fetch(`${API_BASE}/analyses/${id}`).then(handleResponse<AnalysisResponse>),

  deleteAnalysis: (id: string) =>
    fetch(`${API_BASE}/analyses/${id}`, { method: 'DELETE' }).then(handleResponse<{ success: boolean; message: string }>),

  // --- Dashboard ---
  getDashboardSummary: (params?: { category?: string; severity?: string; status?: string; days?: number }) => {
    const query = new URLSearchParams();
    if (params?.category) query.append('category', params.category);
    if (params?.severity) query.append('severity', params.severity);
    if (params?.status) query.append('status', params.status);
    if (params?.days) query.append('days', String(params.days));
    return fetch(`${API_BASE}/dashboard/summary?${query.toString()}`).then(handleResponse<DashboardSummaryData>);
  },

  // --- Indicators ---
  getIndicators: (params?: { q?: string; type?: string; status?: string }) => {
    const query = new URLSearchParams();
    if (params?.q) query.append('q', params.q);
    if (params?.type) query.append('type', params.type);
    if (params?.status) query.append('status', params.status);
    return fetch(`${API_BASE}/indicators?${query.toString()}`).then(handleResponse<IndicatorDetail[]>);
  },

  getIndicatorDetail: (id: string) =>
    fetch(`${API_BASE}/indicators/${id}`).then(handleResponse<IndicatorDetail>),

  updateIndicator: (id: string, verification_status?: string, analyst_note?: string) =>
    fetch(`${API_BASE}/indicators/${id}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ verification_status, analyst_note }),
    }).then(handleResponse<IndicatorDetail>),

  enrichIndicator: (id: string) =>
    fetch(`${API_BASE}/indicators/${id}/enrich`, { method: 'POST' }).then(handleResponse<any>),

  // --- Reports ---
  getReport: (id: string) =>
    fetch(`${API_BASE}/reports/${id}`).then(handleResponse<any>),

  exportReportUrl: (id: string, format: 'json' | 'markdown' | 'csv') =>
    `${API_BASE}/reports/${id}/export?format=${format}`,

  // --- Techniques ---
  getTechniques: (params?: { q?: string; tactic?: string }) => {
    const query = new URLSearchParams();
    if (params?.q) query.append('q', params.q);
    if (params?.tactic) query.append('tactic', params.tactic);
    return fetch(`${API_BASE}/attack/techniques?${query.toString()}`).then(handleResponse<AttackTechniqueRef[]>);
  },

  // --- Feed ---
  getFeed: (params?: { q?: string; category?: string; severity?: string; source?: string }) => {
    const query = new URLSearchParams();
    if (params?.q) query.append('q', params.q);
    if (params?.category) query.append('category', params.category);
    if (params?.severity) query.append('severity', params.severity);
    if (params?.source) query.append('source', params.source);
    return fetch(`${API_BASE}/feed?${query.toString()}`).then(handleResponse<IntelligenceFeedItem[]>);
  },

  syncCisaFeed: () =>
    fetch(`${API_BASE}/feed/sync-cisa`, { method: 'POST' }).then(handleResponse<{ success: boolean; added_count: number; message: string }>),

  // --- Models ---
  getModelStatus: () =>
    fetch(`${API_BASE}/model/status`).then(handleResponse<any>),

  getModelEvaluation: () =>
    fetch(`${API_BASE}/model/evaluation`).then(handleResponse<ModelEvaluationData>),

  trainModel: (algorithm: string = 'Logistic Regression') =>
    fetch(`${API_BASE}/model/train`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ algorithm }),
    }).then(handleResponse<any>),

  // --- System & Demo ---
  getHealth: () =>
    fetch(`${API_BASE}/health`).then(handleResponse<SystemHealth>),

  getSettings: () =>
    fetch(`${API_BASE}/settings`).then(handleResponse<any>),

  getAuditLogs: () =>
    fetch(`${API_BASE}/audit-logs`).then(handleResponse<any[]>),

  importDemoData: () =>
    fetch(`${API_BASE}/demo/import`, { method: 'POST' }).then(handleResponse<{ success: boolean; imported_count: number; message: string }>),

  clearDemoData: () =>
    fetch(`${API_BASE}/demo/clear`, { method: 'POST' }).then(handleResponse<{ success: boolean; removed_count: number; message: string }>),
};
