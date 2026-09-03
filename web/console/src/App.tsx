// App.tsx - 路由根组件。
import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom';
import { Layout } from '@/components/Layout';
import { DashboardPage } from '@/pages/DashboardPage';
import { InterfacesPage } from '@/pages/InterfacesPage';
import { RoutesPage } from '@/pages/RoutesPage';
import { SystemPage } from '@/pages/SystemPage';
import { TrafficPage } from '@/pages/TrafficPage';

export function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route element={<Layout />}>
          <Route path="/" element={<DashboardPage />} />
          <Route path="/interfaces" element={<InterfacesPage />} />
          <Route path="/routes" element={<RoutesPage />} />
          <Route path="/traffic" element={<TrafficPage />} />
          <Route path="/system" element={<SystemPage />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Route>
      </Routes>
    </BrowserRouter>
  );
}
