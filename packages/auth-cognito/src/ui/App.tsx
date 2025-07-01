import React from 'react';
import { HashRouter, Routes, Route, Navigate } from 'react-router-dom';
import ErrorBoundary from './components/ui/ErrorBoundary';
import SignInPage from './components/pages/SignInPage';
import SignUpPage from './components/pages/SignUpPage';
import ConfirmSignUpPage from './components/pages/ConfirmSignUpPage';
import ForgotPasswordPage from './components/pages/ForgotPasswordPage';
import ConfirmForgotPasswordPage from './components/pages/ConfirmForgotPasswordPage';
import SetNewPasswordPage from './components/pages/SetNewPasswordPage';
import MfaPage from './components/pages/MfaPage';
import MagicLinkRequestPage from './components/pages/MagicLinkRequestPage';
import MagicLinkConfirmPage from './components/pages/MagicLinkConfirmPage';
import OAuthCallbackPage from './components/pages/OAuthCallbackPage';
import type { UIConfig } from './types';

interface AppProps { config: UIConfig; }

// Route path constants for the UI
export const ROUTES = {
  root: '/',
  signIn: '/signin',
  signUp: '/signup',
  confirmSignUp: '/confirm-signup',
  forgotPassword: '/forgot-password',
  confirmForgotPassword: '/confirm-forgot',
  setNewPassword: '/set-new-password',
  mfa: '/mfa',
  magicLinkRequest: '/magic',
  magicLinkConfirm: '/magic/verify',
  oauthCallback: '/callback',
  default: '*',
};

const App: React.FC<AppProps> = ({ config }) => {
  const features: any = config.features || {};
  return (
    <ErrorBoundary>
      <HashRouter>
        <Routes>
          <Route path={ROUTES.root} element={<Navigate to={ROUTES.signIn} />} />
          <Route path={ROUTES.signIn} element={<SignInPage />} />
          {features.signUp?.enabled && <Route path={ROUTES.signUp} element={<SignUpPage />} />}
          {features.signUp?.enabled && <Route path={ROUTES.confirmSignUp} element={<ConfirmSignUpPage />} />}
          {features.forgotPassword?.enabled && <Route path={ROUTES.forgotPassword} element={<ForgotPasswordPage />} />}
          {features.forgotPassword?.enabled && <Route path={ROUTES.confirmForgotPassword} element={<ConfirmForgotPasswordPage />} />}
          <Route path={ROUTES.setNewPassword} element={<SetNewPasswordPage />} />
          {features.mfa?.enabled && <Route path={ROUTES.mfa} element={<MfaPage />} />}
          {features.passwordless?.enabled && <Route path={features.passwordless.loginPath} element={<MagicLinkRequestPage />} />}
          {features.passwordless?.enabled && <Route path={features.passwordless.confirmPath} element={<MagicLinkConfirmPage />} />}
          {(features.pkce?.enabled || features.social?.enabled) && <Route path={features.pkce?.redirectPath || features.social?.callbackPath || ROUTES.oauthCallback} element={<OAuthCallbackPage />} />}
          {/* Fallback to sign-in for unknown routes */}
          <Route path={ROUTES.default} element={<Navigate to={ROUTES.signIn} />} />
        </Routes>
      </HashRouter>
    </ErrorBoundary>
  );
};

export default App; 