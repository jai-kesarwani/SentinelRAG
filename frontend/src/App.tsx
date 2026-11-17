import { BrowserRouter, Routes, Route } from 'react-router-dom';
import { AuthProvider } from './context/AuthContext';
import { ProtectedRoute } from './components/auth/ProtectedRoute';
import { AppLayout } from './layouts/AppLayout';
import { DashboardPage } from './pages/DashboardPage';
import { DocumentsPage } from './pages/DocumentsPage';
import { ChatPage } from './pages/ChatPage';
import { SimulatorPage } from './pages/SimulatorPage';
import { SecurityCenterPage } from './pages/SecurityCenterPage';
import { LoginPage } from './pages/LoginPage';
import { RegisterPage } from './pages/RegisterPage';
import { NotFoundPage } from './pages/NotFoundPage';

export function App() {
  return (
    <BrowserRouter>
      <AuthProvider>
        <Routes>
          {/* Public Auth Routes */}
          <Route path="/login" element={<LoginPage />} />
          <Route path="/register" element={<RegisterPage />} />

          {/* Protected Application Routes */}
          <Route
            path="/"
            element={
              <ProtectedRoute>
                <AppLayout pageTitle="System Overview" pageSubtitle="Real-time Infrastructure Telemetry">
                  <DashboardPage />
                </AppLayout>
              </ProtectedRoute>
            }
          />
          <Route
            path="/documents"
            element={
              <ProtectedRoute>
                <AppLayout pageTitle="Document Management" pageSubtitle="Secure PDF Ingestion & Vector Indexing">
                  <DocumentsPage />
                </AppLayout>
              </ProtectedRoute>
            }
          />
          <Route
            path="/chat"
            element={
              <ProtectedRoute>
                <AppLayout pageTitle="AI Assistant" pageSubtitle="Grounded Document Intelligence & Source Verification">
                  <ChatPage />
                </AppLayout>
              </ProtectedRoute>
            }
          />
          <Route
            path="/simulator"
            element={
              <ProtectedRoute>
                <AppLayout pageTitle="Attack Simulator Lab" pageSubtitle="Adversarial Testing & Security Gateway Auditing">
                  <SimulatorPage />
                </AppLayout>
              </ProtectedRoute>
            }
          />
          <Route
            path="/lab"
            element={
              <ProtectedRoute>
                <AppLayout pageTitle="Attack Simulator Lab" pageSubtitle="Adversarial Testing & Security Gateway Auditing">
                  <SimulatorPage />
                </AppLayout>
              </ProtectedRoute>
            }
          />
          <Route
            path="/security-center"
            element={
              <ProtectedRoute>
                <AppLayout pageTitle="Security Center" pageSubtitle="Real-time Incident Monitoring & Threat Analytics">
                  <SecurityCenterPage />
                </AppLayout>
              </ProtectedRoute>
            }
          />
          <Route
            path="/security"
            element={
              <ProtectedRoute>
                <AppLayout pageTitle="Security Center" pageSubtitle="Real-time Incident Monitoring & Threat Analytics">
                  <SecurityCenterPage />
                </AppLayout>
              </ProtectedRoute>
            }
          />

          {/* 404 Catch-All */}
          <Route
            path="*"
            element={
              <AppLayout pageTitle="Not Found" pageSubtitle="404 Error">
                <NotFoundPage />
              </AppLayout>
            }
          />
        </Routes>
      </AuthProvider>
    </BrowserRouter>
  );
}

export default App;
