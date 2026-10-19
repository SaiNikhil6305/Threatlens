import React, { useEffect, useState } from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';

import { Sidebar } from './components/Sidebar';
import { Header } from './components/Header';
import { OverviewPage } from './pages/OverviewPage';
import { AnalyzePage } from './pages/AnalyzePage';
import { FeedPage } from './pages/FeedPage';
import { IndicatorsPage } from './pages/IndicatorsPage';
import { TechniquesPage } from './pages/TechniquesPage';
import { ReportsPage } from './pages/ReportsPage';
import { HistoryPage } from './pages/HistoryPage';
import { ModelEvaluationPage } from './pages/ModelEvaluationPage';
import { SettingsPage } from './pages/SettingsPage';
import { api } from './services/api';
import { SystemHealth } from './types';

import { ToastProvider } from './context/ToastContext';

export const App: React.FC = () => {
  const [health, setHealth] = useState<SystemHealth | undefined>(undefined);

  useEffect(() => {
    const checkHealth = async () => {
      try {
        const data = await api.getHealth();
        setHealth(data);
      } catch {
        // backend might be starting
      }
    };
    checkHealth();
  }, []);

  return (
    <ToastProvider>
      <BrowserRouter>
        <div className="flex h-screen w-screen overflow-hidden bg-background text-charcoal-900 font-sans">
        {/* Left Persistent Navigation */}
        <Sidebar systemHealth={health} />

        {/* Right Content Area */}
        <div className="flex flex-1 flex-col overflow-hidden">
          <Header systemHealth={health} />

          <main className="flex-1 overflow-y-auto p-8">
            <div className="max-w-7xl mx-auto">
              <Routes>
                <Route path="/" element={<OverviewPage />} />
                <Route path="/overview" element={<Navigate to="/" replace />} />
                <Route path="/analyze" element={<AnalyzePage />} />
                <Route path="/feed" element={<FeedPage />} />
                <Route path="/indicators" element={<IndicatorsPage />} />
                <Route path="/techniques" element={<TechniquesPage />} />
                <Route path="/reports" element={<ReportsPage />} />
                <Route path="/history" element={<HistoryPage />} />
                <Route path="/model-evaluation" element={<ModelEvaluationPage />} />
                <Route path="/settings" element={<SettingsPage />} />
                <Route path="*" element={<Navigate to="/" replace />} />
              </Routes>
            </div>
          </main>
        </div>
      </div>
    </BrowserRouter>
  </ToastProvider>
  );
};

export default App;
