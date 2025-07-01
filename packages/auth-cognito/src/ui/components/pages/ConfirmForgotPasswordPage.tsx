import React, { useState } from 'react';
import { useNavigate, useLocation, Link } from 'react-router-dom';
import { confirmForgotPassword } from '../../services/api';
import TextInput from '../ui/TextInput';
import Button from '../ui/Button';
import { useTranslation } from 'react-i18next';

interface LocationState {
  email: string;
}

const ConfirmForgotPasswordPage: React.FC = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const state = location.state as LocationState;
  const email = state?.email || '';
  const [code, setCode] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const { t } = useTranslation();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    try {
      await confirmForgotPassword(email, code, newPassword);
      navigate('/signin');
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <form onSubmit={handleSubmit}>
      <h2>{t('confirmForgotPassword.title')}</h2>
      <TextInput label={t('confirmForgotPassword.codeLabel')} value={code} onChange={e => setCode(e.target.value)} placeholder={t('confirmForgotPassword.codeLabel')} />
      <TextInput label={t('confirmForgotPassword.newPasswordLabel')} type="password" value={newPassword} onChange={e => setNewPassword(e.target.value)} placeholder={t('confirmForgotPassword.newPasswordLabel')} />
      <Button type="submit" loading={loading}>{t('confirmForgotPassword.button')}</Button>
      {error && <div className="auth-error">{error}</div>}
      <div className="auth-links">
        <Link to="/signin" className="auth-link">{t('signUp.backLink')}</Link>
      </div>
    </form>
  );
};

export default ConfirmForgotPasswordPage; 