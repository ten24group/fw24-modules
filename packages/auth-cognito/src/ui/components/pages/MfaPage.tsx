import React, { useState, useEffect } from 'react';
import { useNavigate, useLocation, Link } from 'react-router-dom';
import { respondToOtpChallenge, SignInResponse } from '../../services/api';
import TextInput from '../ui/TextInput';
import Button from '../ui/Button';
import { useTranslation } from 'react-i18next';
import config from '../../config.json';

interface LocationState {
  username: string;
  session: string;
  challengeName: string;
  challengeParameters?: Record<string, string>;
}

const MfaPage: React.FC = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const state = location.state as LocationState;
  const { username, session } = state;
  const [code, setCode] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [selectedMethod, setSelectedMethod] = useState<string | null>(null);
  const { t } = useTranslation();

  const mfaMethods = config.features?.mfa?.methods || [];
  
  // Auto-select method if only one is configured
  useEffect(() => {
    if (mfaMethods.length === 1) {
      setSelectedMethod(mfaMethods[0]);
    }
  }, [mfaMethods]);

  const handleMethodSelect = (method: string) => {
    setSelectedMethod(method);
    // Here you would call an API to initiate the chosen MFA method, e.g.,
    // initiateSmsMfa(username, session) or initiateTotpMfa(username, session)
    // For this example, we assume the challenge is already initiated.
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    try {
      const response = await respondToOtpChallenge(username, session, code);
      if ('IdToken' in response) {
        window.parent.dispatchEvent(new CustomEvent('auth:success', { detail: response as SignInResponse }));
      }
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  if (mfaMethods.length > 1 && !selectedMethod) {
    return (
      <div>
        <h2>{t('mfaSelect.title')}</h2>
        <p>{t('mfaSelect.prompt')}</p>
        {mfaMethods.includes('SMS') && <Button onClick={() => handleMethodSelect('SMS')}>{t('mfaSelect.smsButton')}</Button>}
        {mfaMethods.includes('TOTP') && <Button onClick={() => handleMethodSelect('TOTP')}>{t('mfaSelect.totpButton')}</Button>}
      </div>
    );
  }

  return (
    <form onSubmit={handleSubmit}>
      <h2>{t('mfa.title')}</h2>
      <p>{t('mfa.prompt')}</p>
      <TextInput label={t('mfa.codeLabel')} value={code} onChange={e => setCode(e.target.value)} placeholder="MFA code" />
      <Button type="submit" loading={loading}>{t('mfa.button')}</Button>
      {error && <div className="auth-error">{error}</div>}
      <div className="auth-links">
        <Link to="/signin" className="auth-link">{t('mfa.cancelLink')}</Link>
      </div>
    </form>
  );
};

export default MfaPage; 