import React from 'react';
import { HashRouter, Routes, Route, Navigate } from 'react-router-dom';
import ErrorBoundary from './components/ui/ErrorBoundary';
import SignInPage from './components/pages/SignInPage';
import SignUpPage from './components/pages/SignUpPage';
import ConfirmSignUpPage from './components/pages/ConfirmSignUpPage';
import ForgotPasswordPage from './components/pages/ForgotPasswordPage';
import ConfirmForgotPasswordPage from './components/pages/ConfirmForgotPasswordPage';
import MfaPage from './components/pages/MfaPage';
import config from './config.json';

const App: React.FC = () => {
  const features = (config as any).features || {};
  return (
    <ErrorBoundary>
      <HashRouter>
        <Routes>
          <Route path="/" element={<Navigate to="/signin" />} />
          <Route path="/signin" element={<SignInPage />} />
          {features.signUp && <Route path="/signup" element={<SignUpPage />} />}
          {features.signUp && <Route path="/confirm-signup" element={<ConfirmSignUpPage />} />}
          {features.forgotPassword && <Route path="/forgot-password" element={<ForgotPasswordPage />} />}
          {features.forgotPassword && <Route path="/confirm-forgot" element={<ConfirmForgotPasswordPage />} />}
          {features.mfa && <Route path="/mfa" element={<MfaPage />} />}
          {/* Fallback to sign-in for unknown routes */}
          <Route path="*" element={<Navigate to="/signin" />} />
        </Routes>
      </HashRouter>
    </ErrorBoundary>
  );
};

export default App; 