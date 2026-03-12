import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import Layout from './components/Layout';
import Dashboard from './pages/Dashboard';
import Scans from './pages/Scans';
import ScanDetail from './pages/ScanDetail';
import Policies from './pages/Policies';
import SBOMViewer from './pages/SBOMViewer';
import AuditLog from './pages/AuditLog';
import Settings from './pages/Settings';
import Workers from './pages/Workers';
import Registries from './pages/Registries';
import SeedScans from './pages/SeedScans';
import Teams from './pages/Teams';
import TeamDashboard from './pages/TeamDashboard';

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 1,
      refetchOnWindowFocus: false,
    },
  },
});

export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <Routes>
          <Route path="/" element={<Layout />}>
            <Route index element={<Navigate to="/dashboard" replace />} />
            <Route path="dashboard" element={<Dashboard />} />
            <Route path="scans" element={<Scans />} />
            <Route path="scans/:id" element={<ScanDetail />} />
            <Route path="policies" element={<Policies />} />
            <Route path="sbom/:scanId" element={<SBOMViewer />} />
            <Route path="audit-log" element={<AuditLog />} />
            <Route path="settings" element={<Settings />} />
            <Route path="workers" element={<Workers />} />
            <Route path="registries" element={<Registries />} />
            <Route path="teams" element={<Teams />} />
            <Route path="teams/:teamId/dashboard" element={<TeamDashboard />} />
            <Route path="seed" element={<SeedScans />} />
          </Route>
        </Routes>
      </BrowserRouter>
    </QueryClientProvider>
  );
}
