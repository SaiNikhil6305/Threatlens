import React, { useEffect, useState } from 'react';
import {
  BarChart3,
  Cpu,
  RefreshCw,
  CheckCircle2,
  Info,
  Layers,
  Award,
  AlertCircle,
  Sparkles,
  TrendingUp
} from 'lucide-react';

import { api } from '../services/api';
import { ModelEvaluationData } from '../types';
import { LoadingSpinner } from '../components/LoadingSpinner';
import { EmptyState } from '../components/EmptyState';
import { useToast } from '../context/ToastContext';

export const ModelEvaluationPage: React.FC = () => {
  const { showToast } = useToast();
  const [evalData, setEvalData] = useState<ModelEvaluationData | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [training, setTraining] = useState<boolean>(false);
  const [selectedAlgo, setSelectedAlgo] = useState<string>('Logistic Regression');
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const fetchEvaluation = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await api.getModelEvaluation();
      setEvalData(data);
    } catch (err: any) {
      setError(err.message || 'Failed to load model evaluation metrics.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchEvaluation();
  }, []);

  const handleTrain = async () => {
    setTraining(true);
    setMessage(null);
    setError(null);
    showToast(`Training ${selectedAlgo} on threat intelligence dataset...`, 'info');
    try {
      const res = await api.trainModel(selectedAlgo);
      const msg = `Successfully trained and evaluated ${selectedAlgo} (${res.version}).`;
      setMessage(msg);
      showToast(msg, 'success');
      await fetchEvaluation();
    } catch (err: any) {
      setError(err.message || 'Model training failed.');
      showToast(err.message || 'Model training failed.', 'error');
    } finally {
      setTraining(false);
    }
  };

  if (loading && !evalData) {
    return <LoadingSpinner message="Loading machine learning evaluation metrics..." />;
  }

  const hasTrainedModel = evalData && evalData.has_trained_model && evalData.details;

  return (
    <div className="space-y-6">
      {/* Top Controls Header */}
      <div className="flex flex-wrap items-center justify-between gap-4 rounded-lg bg-surface p-5 border border-border shadow-sm">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <h2 className="text-sm font-semibold text-charcoal-900">Academic Model Evaluation Benchmarks</h2>
            <span className="font-mono text-[10px] bg-accent/10 text-accent font-semibold px-2 py-0.5 rounded border border-accent/20">
              {evalData?.version || 'v1.0'}
            </span>
          </div>
          <p className="text-xs text-charcoal-500">
            Real supervised evaluation comparing baseline TF-IDF Logistic Regression against Linear SVM
          </p>
        </div>

        <div className="flex items-center gap-3">
          <select
            value={selectedAlgo}
            onChange={(e) => setSelectedAlgo(e.target.value)}
            className="rounded-md border border-border bg-surface px-3 py-1.5 text-xs text-charcoal-800 font-medium focus:outline-none focus:ring-1 focus:ring-accent"
          >
            <option value="Logistic Regression">Logistic Regression (Baseline)</option>
            <option value="Linear SVM">Linear SVM (Comparison)</option>
          </select>

          <button
            type="button"
            disabled={training}
            onClick={handleTrain}
            className="inline-flex items-center gap-1.5 rounded-md bg-navy-900 px-3.5 py-1.5 text-xs font-semibold text-white shadow-sm hover:bg-navy-800 disabled:opacity-50 transition active:scale-[0.98]"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${training ? 'animate-spin' : ''}`} />
            <span>{training ? 'Training Model...' : 'Train & Evaluate'}</span>
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

      {!hasTrainedModel ? (
        <EmptyState
          title="No Model Evaluation Found"
          description="Model artifacts have not been evaluated yet. Run the training pipeline to generate actual test split metrics and confusion matrices."
          actionText="Run Model Training"
          onAction={handleTrain}
        />
      ) : (
        <>
          {/* Key Metric KPI Cards */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            <div className="rounded-lg bg-surface border border-border p-4 shadow-sm interactive-card">
              <span className="text-xs font-medium text-charcoal-500 block mb-1">Accuracy</span>
              <div className="text-2xl font-bold text-charcoal-900 tracking-tight font-mono">
                {((evalData.accuracy || 0) * 100).toFixed(1)}%
              </div>
              <p className="text-[11px] text-charcoal-400 mt-1">Overall stratified test agreement</p>
            </div>

            <div className="rounded-lg bg-surface border border-border p-4 shadow-sm interactive-card">
              <span className="text-xs font-medium text-charcoal-500 block mb-1">Macro Precision</span>
              <div className="text-2xl font-bold text-charcoal-900 tracking-tight font-mono">
                {((evalData.precision || 0) * 100).toFixed(1)}%
              </div>
              <p className="text-[11px] text-charcoal-400 mt-1">Unweighted average precision</p>
            </div>

            <div className="rounded-lg bg-surface border border-border p-4 shadow-sm interactive-card">
              <span className="text-xs font-medium text-charcoal-500 block mb-1">Macro Recall</span>
              <div className="text-2xl font-bold text-charcoal-900 tracking-tight font-mono">
                {((evalData.recall || 0) * 100).toFixed(1)}%
              </div>
              <p className="text-[11px] text-charcoal-400 mt-1">Unweighted average recall</p>
            </div>

            <div className="rounded-lg bg-surface border border-border p-4 shadow-sm interactive-card">
              <span className="text-xs font-medium text-charcoal-500 block mb-1">Macro F1-Score</span>
              <div className="text-2xl font-bold text-charcoal-900 tracking-tight font-mono text-accent">
                {((evalData.f1_score || 0) * 100).toFixed(1)}%
              </div>
              <p className="text-[11px] text-charcoal-400 mt-1">Harmonic mean across classes</p>
            </div>
          </div>

          {/* Model Comparison Table */}
          {evalData.details?.comparison && (
            <div className="rounded-lg bg-surface border border-border p-5 shadow-sm">
              <div className="mb-4">
                <h3 className="text-xs font-bold text-charcoal-900 uppercase tracking-wider">
                  Baseline vs. Comparison Model Evaluation
                </h3>
                <p className="text-xs text-charcoal-500">
                  Direct performance comparison on identical stratified test partitions
                </p>
              </div>

              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs border border-border rounded overflow-hidden">
                  <thead className="bg-surface-subtle text-charcoal-600 border-b border-border font-medium">
                    <tr>
                      <th className="px-5 py-2.5">Architecture</th>
                      <th className="px-5 py-2.5">Role</th>
                      <th className="px-5 py-2.5">Test Accuracy</th>
                      <th className="px-5 py-2.5">Macro Precision</th>
                      <th className="px-5 py-2.5">Macro Recall</th>
                      <th className="px-5 py-2.5">Macro F1</th>
                      <th className="px-5 py-2.5">Status</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border font-mono">
                    <tr className="table-row-hover">
                      <td className="px-5 py-3 font-sans font-semibold text-charcoal-900">Logistic Regression</td>
                      <td className="px-5 py-3 font-sans text-charcoal-500">Baseline (L2 Regularized)</td>
                      <td className="px-5 py-3">{(evalData.details.comparison.logistic_regression?.accuracy * 100).toFixed(1)}%</td>
                      <td className="px-5 py-3">{(evalData.details.comparison.logistic_regression?.precision * 100).toFixed(1)}%</td>
                      <td className="px-5 py-3">{(evalData.details.comparison.logistic_regression?.recall * 100).toFixed(1)}%</td>
                      <td className="px-5 py-3 font-bold text-accent">{(evalData.details.comparison.logistic_regression?.f1_score * 100).toFixed(1)}%</td>
                      <td className="px-5 py-3 font-sans">
                        {evalData.model_name === 'Logistic Regression' && (
                          <span className="text-[10px] bg-emerald-50 text-emerald-700 px-2 py-0.5 rounded border border-emerald-200 font-medium">
                            Active Model
                          </span>
                        )}
                      </td>
                    </tr>
                    <tr className="table-row-hover">
                      <td className="px-5 py-3 font-sans font-semibold text-charcoal-900">Linear SVM (LinearSVC)</td>
                      <td className="px-5 py-3 font-sans text-charcoal-500">Comparison (Support Vector)</td>
                      <td className="px-5 py-3">{(evalData.details.comparison.linear_svm?.accuracy * 100).toFixed(1)}%</td>
                      <td className="px-5 py-3">{(evalData.details.comparison.linear_svm?.precision * 100).toFixed(1)}%</td>
                      <td className="px-5 py-3">{(evalData.details.comparison.linear_svm?.recall * 100).toFixed(1)}%</td>
                      <td className="px-5 py-3 font-bold text-accent">{(evalData.details.comparison.linear_svm?.f1_score * 100).toFixed(1)}%</td>
                      <td className="px-5 py-3 font-sans">
                        {evalData.model_name === 'Linear SVM' && (
                          <span className="text-[10px] bg-emerald-50 text-emerald-700 px-2 py-0.5 rounded border border-emerald-200 font-medium">
                            Active Model
                          </span>
                        )}
                      </td>
                    </tr>
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* Per-Class Metrics Table */}
          {evalData.details?.metrics?.per_class && (
            <div className="rounded-lg bg-surface border border-border shadow-sm overflow-hidden">
              <div className="border-b border-border px-5 py-3.5">
                <h3 className="text-xs font-bold text-charcoal-900 uppercase tracking-wider">
                  Per-Class Classification Metrics ({evalData.model_name})
                </h3>
                <p className="text-xs text-charcoal-500">Evaluated on stratified hold-out test partition</p>
              </div>

              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs">
                  <thead className="bg-surface-subtle text-charcoal-600 border-b border-border font-medium">
                    <tr>
                      <th className="px-5 py-2.5">Threat Category</th>
                      <th className="px-5 py-2.5">Precision</th>
                      <th className="px-5 py-2.5">Recall</th>
                      <th className="px-5 py-2.5">F1-Score</th>
                      <th className="px-5 py-2.5 text-center">Test Support</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border">
                    {Object.entries(evalData.details.metrics.per_class).map(([className, m]) => (
                      <tr key={className} className="table-row-hover font-mono">
                        <td className="px-5 py-2.5 font-sans font-medium text-charcoal-900">
                          {className}
                        </td>
                        <td className="px-5 py-2.5 text-charcoal-700">
                          {(m.precision * 100).toFixed(1)}%
                        </td>
                        <td className="px-5 py-2.5 text-charcoal-700">
                          {(m.recall * 100).toFixed(1)}%
                        </td>
                        <td className="px-5 py-2.5 font-bold text-charcoal-900">
                          {(m.f1_score * 100).toFixed(1)}%
                        </td>
                        <td className="px-5 py-2.5 text-center text-charcoal-500">
                          {m.support}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* Confusion Matrix Heatmap Table */}
          {evalData.details?.metrics?.confusion_matrix && (
            <div className="rounded-lg bg-surface border border-border p-5 shadow-sm overflow-hidden">
              <div className="flex items-center justify-between mb-4">
                <div>
                  <h3 className="text-xs font-bold text-charcoal-900 uppercase tracking-wider">
                    Confusion Matrix Heatmap
                  </h3>
                  <p className="text-xs text-charcoal-500">
                    Rows represent Ground Truth, Columns represent Model Predictions
                  </p>
                </div>
                <div className="flex items-center gap-3 text-[11px] font-sans">
                  <span className="flex items-center gap-1.5">
                    <span className="h-3 w-3 rounded bg-emerald-600 inline-block" />
                    <span>Correct (Diagonal)</span>
                  </span>
                  <span className="flex items-center gap-1.5">
                    <span className="h-3 w-3 rounded bg-red-100 border border-red-300 inline-block" />
                    <span>Misclassified</span>
                  </span>
                </div>
              </div>

              <div className="overflow-x-auto">
                <table className="text-center text-xs font-mono border border-border w-full">
                  <thead>
                    <tr className="bg-surface-subtle text-[10px] text-charcoal-600">
                      <th className="p-2.5 text-left font-sans border-r border-border min-w-[130px]">
                        True \ Predicted
                      </th>
                      {evalData.details.metrics.labels.map((lbl, idx) => (
                        <th key={idx} className="p-2 border-r border-border truncate max-w-[80px]" title={lbl}>
                          {lbl.slice(0, 4)}..
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {evalData.details.metrics.confusion_matrix.map((row, rIdx) => (
                      <tr key={rIdx} className="border-t border-border">
                        <td
                          className="p-2.5 text-left font-sans text-[11px] font-medium text-charcoal-800 border-r border-border truncate max-w-[150px]"
                          title={evalData.details!.metrics.labels[rIdx]}
                        >
                          {evalData.details!.metrics.labels[rIdx]}
                        </td>
                        {row.map((cell, cIdx) => {
                          const isDiagonal = rIdx === cIdx;
                          let cellClass = 'p-2 border-r border-border text-center ';

                          if (isDiagonal) {
                            if (cell > 0) {
                              cellClass += 'bg-emerald-600 text-white font-bold shadow-2xs';
                            } else {
                              cellClass += 'text-charcoal-400';
                            }
                          } else {
                            if (cell > 0) {
                              cellClass += 'bg-red-50 text-red-800 font-semibold border-red-100';
                            } else {
                              cellClass += 'text-charcoal-300';
                            }
                          }

                          return (
                            <td key={cIdx} className={cellClass}>
                              {cell}
                            </td>
                          );
                        })}
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* Academic Notes & Dataset Caveats */}
          <div className="rounded-lg bg-surface-subtle border border-border p-5 text-xs text-charcoal-600 space-y-2">
            <div className="flex items-center gap-1.5 font-semibold text-charcoal-900">
              <Info className="h-4 w-4 text-accent" />
              <span>Methodological Disclosures & Scientific Validity</span>
            </div>
            <p>
              Machine learning models evaluated above operate on TF-IDF word & bi-gram n-gram features (max 5,000 features).
              Test partitions are formed using stratified shuffle splitting to preserve class balance.
            </p>
            <p>
              Model performance is bounded by dataset representativeness, sentence structure diversity, and class balance.
              Real SOC deployments should continuously retrain models on verified enterprise incident corpora and retain human analyst review.
            </p>
          </div>
        </>
      )}
    </div>
  );
};
