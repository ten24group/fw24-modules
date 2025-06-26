import React from 'react';
import { HashRouter, Routes, Route, Navigate } from 'react-router-dom';
import ErrorBoundary from './components/ui/ErrorBoundary';
import SignInPage from './components/pages/SignInPage';
import SignUpPage from './components/pages/SignUpPage';
import ConfirmSignUpPage from './components/pages/ConfirmSignUpPage';
import ForgotPasswordPage from './components/pages/ForgotPasswordPage';
import ConfirmForgotPasswordPage from './components/pages/ConfirmForgotPasswordPage';
import MfaPage from './components/pages/MfaPage';
import MagicLinkRequestPage from './components/pages/MagicLinkRequestPage';
import MagicLinkConfirmPage from './components/pages/MagicLinkConfirmPage';
import OAuthCallbackPage from './components/pages/OAuthCallbackPage';
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
          {features.mfa?.enabled && <Route path="/mfa" element={<MfaPage />} />}
          {features.passwordless?.enabled && <Route path={features.passwordless.loginPath} element={<MagicLinkRequestPage />} />}
          {features.passwordless?.enabled && <Route path={features.passwordless.confirmPath} element={<MagicLinkConfirmPage />} />}
          {(features.pkce?.enabled || features.social?.enabled) && <Route path={features.pkce?.redirectPath || features.social?.callbackPath} element={<OAuthCallbackPage />} />}
          
          {/* Fallback to sign-in for unknown routes */}
          <Route path="*" element={<Navigate to="/signin" />} />
        </Routes>
      </HashRouter>
    </ErrorBoundary>
  );
};

export default App; 