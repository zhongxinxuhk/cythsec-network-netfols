// App.tsx - 路由根组件。
import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom';
import { Layout } from '@/components/Layout';
import { InterfacesPage } from '@/pages/InterfacesPage';
import { RoutesPage } from '@/pages/RoutesPage';
import { SystemPage } from '@/pages/SystemPage';

export function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route element={<Layout />}>
          <Route path="/" element={<SystemPage />} />
          <Route path="/interfaces" element={<InterfacesPage />} />
          <Route path="/routes" element={<RoutesPage />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Route>
      </Routes>
    </BrowserRouter>
  );
}
