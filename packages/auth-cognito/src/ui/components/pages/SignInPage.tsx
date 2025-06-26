import React, { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { signIn, SignInResponse, Challenge, socialSignIn } from '../../services/api';
import TextInput from '../ui/TextInput';
import Button from '../ui/Button';
import config from '../../config.json';
import { useTranslation } from 'react-i18next';
import { redirectToAuthorize } from '../../services/oauth';

const SignInPage: React.FC = () => {
  const [identifier, setIdentifier] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const navigate = useNavigate();
  const { t } = useTranslation();
  const features = (config as any).features || {};

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    try {
      const response = await signIn({ username: identifier, password });
      if ('challengeName' in response) {
        // pass username and challenge data via navigation state for MFA
        const challenge = response as Challenge;
        navigate('/mfa', {
          state: {
            username: identifier,
            session: challenge.session,
            challengeName: challenge.challengeName,
            challengeParameters: challenge.challengeParameters,
          },
        });
      } else {
        // successful login
        window.parent.dispatchEvent(new CustomEvent('auth:success', { detail: response as SignInResponse }));
      }
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleSocialSignIn = (provider: any) => {
    // Redirect user to social provider OAuth2 authorization
    const redirectUri = encodeURIComponent(window.location.origin + (features.social.callbackPath || ''));
    window.location.href = `${provider.authorizeUrl}?response_type=code&client_id=${provider.clientId}&redirect_uri=${redirectUri}&scope=${provider.scope}`;
  }

  return (
    <form onSubmit={handleSubmit}>
      <h2>{t('signIn.title')}</h2>
      <TextInput label={t('signIn.userLabel')} value={identifier} onChange={e => setIdentifier(e.target.value)} placeholder="Username or Email" />
      <TextInput label={t('signIn.passwordLabel')} type="password" value={password} onChange={e => setPassword(e.target.value)} placeholder="Password" />

      {features.pkce?.enabled && (
        <>
          <div style={{ textAlign: 'center', margin: '1rem 0' }}>{t('signIn.or')}</div>
          <Button type="button" onClick={redirectToAuthorize}>{t('signIn.pkceButton')}</Button>
        </>
      )}

      {features.social?.enabled && (
        <div style={{ margin: '1rem 0' }}>
          {(features.social.providers || []).map((provider: any) => (
            <Button key={provider.id} type="button" onClick={() => handleSocialSignIn(provider)} style={{ marginTop: '0.5rem' }}>
              {t('social.signInWith', { provider: provider.id })}
            </Button>
          ))}
        </div>
      )}
      <Button type="submit" loading={loading}>{t('signIn.button')}</Button>
      {error && <div className="auth-error">{error}</div>}
      <div className="auth-links">
        {features.signUp && <Link to="/signup" className="auth-link">{t('signIn.signUpLink')}</Link>}
        {features.signUp && features.forgotPassword && ' | '}
        {features.forgotPassword && <Link to="/forgot-password" className="auth-link">{t('signIn.forgotPasswordLink')}</Link>}
      </div>
    </form>
  );
};

export default SignInPage; 