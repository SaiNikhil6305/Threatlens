export type SeverityLevel = 'Critical' | 'High' | 'Medium' | 'Low' | 'Informational';

export type IndicatorType = 'ipv4' | 'domain' | 'url' | 'email' | 'md5' | 'sha1' | 'sha256' | 'cve';

export interface IndicatorItem {
  id?: string;
  original_value: string;
  normalized_value: string;
  defanged_value: string;
  indicator_type: IndicatorType;
  reputation_status?: string;
  reputation_source?: string;
  verification_status?: string;
  evidence_snippet?: string;
  confidence?: number;
}

export interface EntityItem {
  id?: string;
  entity_type: string;
  entity_value: string;
  evidence_snippet?: string;
  confidence?: number;
  verification_status?: string;
}

export interface TechniqueItem {
  technique_id: string;
  technique_name: string;
  tactic: string;
  description?: string;
  evidence?: string;
  mapping_confidence?: number;
  verification_status?: string;
  url?: string;
}

export interface DefensiveRecommendation {
  action: string;
  detail: string;
}

export interface SeverityRationale {
  severity: SeverityLevel;
  severity_score: number;
  triggered_rules: Array<{
    rule: string;
    description: string;
    weight: number;
  }>;
  missing_information: string[];
  recommended_investigation_steps: string[];
  assessment_disclaimer?: string;
}

export interface AnalysisResponse {
  id: string;
  title: string;
  original_text: string;
  input_type: string;
  file_name?: string;
  source?: string;
  predicted_category: string;
  confidence: number;
  prediction_method: string;
  model_version?: string;
  is_uncertain: boolean;
  severity: SeverityLevel;
  severity_score: number;
  severity_rationale: SeverityRationale;
  defensive_recommendations: DefensiveRecommendation[];
  indicators: IndicatorItem[];
  entities: EntityItem[];
  techniques: TechniqueItem[];
  notes: Array<{
    id: string;
    author: string;
    note: string;
    created_at: string;
  }>;
  status: string;
  created_at: string;
  updated_at: string;
}

export interface AnalysisSummary {
  id: string;
  title: string;
  input_type: string;
  predicted_category: string;
  severity: SeverityLevel;
  confidence: number;
  prediction_method: string;
  indicators_count: number;
  created_at: string;
  status: string;
}

export interface DashboardSummaryData {
  total_reports: number;
  total_indicators: number;
  high_critical_count: number;
  top_threat_category: string;
  pending_review_count: number;
  category_distribution: Record<string, number>;
  severity_distribution: Record<string, number>;
  indicator_distribution: Record<string, number>;
  activity_timeline: Array<{ date: string; count: number }>;
  recent_investigations: Array<{
    id: string;
    title: string;
    predicted_category: string;
    severity: SeverityLevel;
    confidence: number;
    indicator_count: number;
    status: string;
    created_at: string;
  }>;
}

export interface IndicatorDetail {
  id: string;
  normalized_value: string;
  original_value: string;
  defanged_value: string;
  indicator_type: IndicatorType;
  reputation_status: string;
  reputation_source?: string;
  verification_status: string;
  associated_reports_count: number;
  associated_reports: Array<{
    analysis_id: string;
    title: string;
    category: string;
    severity: string;
    created_at: string;
    evidence_snippet?: string;
  }>;
  analyst_notes: Array<{
    id: string;
    author: string;
    note: string;
    created_at: string;
  }>;
  first_observed: string;
  last_observed: string;
  last_enriched_at?: string;
}

export interface AttackTechniqueRef {
  id: string;
  technique_id: string;
  technique_name: string;
  tactic: string;
  description?: string;
  mapping_source?: string;
  url?: string;
  investigation_count: number;
}

export interface IntelligenceFeedItem {
  id: string;
  title: string;
  source: string;
  publication_date: string;
  threat_category: string;
  severity: SeverityLevel;
  indicators: string[];
  summary: string;
  url?: string;
  is_local: boolean;
}

export interface ModelEvaluationData {
  has_trained_model: boolean;
  version?: string;
  model_name?: string;
  dataset_reference?: string;
  accuracy?: number;
  precision?: number;
  recall?: number;
  f1_score?: number;
  created_at?: string;
  message?: string;
  details?: {
    selected_model: string;
    metrics: {
      accuracy: number;
      precision: number;
      recall: number;
      f1_score: number;
      per_class: Record<string, { precision: number; recall: number; f1_score: number; support: number }>;
      confusion_matrix: number[][];
      labels: string[];
    };
    comparison?: {
      logistic_regression: any;
      linear_svm: any;
    };
    class_distribution?: Record<string, number>;
    train_samples?: number;
    test_samples?: number;
  };
}

export interface SystemHealth {
  status: string;
  project: string;
  tagline: string;
  database: string;
  ml_model_loaded: boolean;
  integrations: {
    virustotal: boolean;
    alienvault_otx: boolean;
  };
}
