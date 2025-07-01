import React, { useState } from 'react';
import { useNavigate, useLocation, Link } from 'react-router-dom';
import { confirmSignUp } from '../../services/api';
import TextInput from '../ui/TextInput';
import Button from '../ui/Button';
import { useTranslation } from 'react-i18next';

interface LocationState {
  email: string;
}

const ConfirmSignUpPage: React.FC = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const state = location.state as LocationState;
  const email = state?.email || '';
  const [code, setCode] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const { t } = useTranslation();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    try {
      await confirmSignUp(email, code);
      navigate('/signin');
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <form onSubmit={handleSubmit}>
      <h2>{t('confirmSignUp.title')}</h2>
      <p>{t('confirmSignUp.prompt')}</p>
      <TextInput label={t('confirmSignUp.codeLabel')} value={code} onChange={e => setCode(e.target.value)} placeholder={t('confirmSignUp.codeLabel')} />
      <Button type="submit" loading={loading}>{t('confirmSignUp.button')}</Button>
      {error && <div className="auth-error">{error}</div>}
      <div className="auth-links">
        <Link to="/signup" className="auth-link">{t('confirmSignUp.backToSignUpLink')}</Link>{' | '}
        <Link to="/signin" className="auth-link">{t('signUp.backLink')}</Link>
      </div>
    </form>
  );
};

export default ConfirmSignUpPage; 