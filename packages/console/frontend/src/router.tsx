import { lazy, Suspense } from "react";
import { Routes, Route, Navigate } from "react-router-dom";

const DashboardPage = lazy(() => import("./pages/DashboardPage"));
const TracesPage = lazy(() => import("./pages/TracesPage"));
const TraceDetailPage = lazy(() => import("./pages/TraceDetailPage"));
const PoliciesPage = lazy(() => import("./pages/PoliciesPage"));
const RulesPage = lazy(() => import("./pages/RulesPage"));
const AlertsPage = lazy(() => import("./pages/AlertsPage"));
const AgentsPage = lazy(() => import("./pages/AgentsPage"));
const SourcesPage = lazy(() => import("./pages/SourcesPage"));
const SettingsPage = lazy(() => import("./pages/SettingsPage"));

function PageLoader() {
  return (
    <div className="flex items-center justify-center h-64">
      <div className="w-8 h-8 border-2 border-accent border-t-transparent rounded-full animate-spin" />
    </div>
  );
}

export function AppRoutes() {
  return (
    <Suspense fallback={<PageLoader />}>
      <Routes>
        <Route path="/" element={<Navigate to="/dashboard" replace />} />
        <Route path="/dashboard" element={<DashboardPage />} />
        <Route path="/traces" element={<TracesPage />} />
        <Route path="/traces/:traceId" element={<TraceDetailPage />} />
        <Route path="/policies" element={<PoliciesPage />} />
        <Route path="/rules" element={<RulesPage />} />
        <Route path="/alerts" element={<AlertsPage />} />
        <Route path="/agents" element={<AgentsPage />} />
        <Route path="/sources" element={<SourcesPage />} />
        <Route path="/settings" element={<SettingsPage />} />
      </Routes>
    </Suspense>
  );
}
