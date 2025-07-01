import React, { useState } from 'react';
import { useNavigate, useLocation, Link } from 'react-router-dom';
import { setNewPassword } from '../../services/api';
import TextInput from '../ui/TextInput';
import Button from '../ui/Button';
import { useTranslation } from 'react-i18next';

interface LocationState {
  email: string;
  session: string;
}

const SetNewPasswordPage: React.FC = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const state = location.state as LocationState;
  const email = state?.email || '';
  const session = state?.session || '';
  const [newPassword, setNewPasswordValue] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const { t } = useTranslation();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    if (newPassword !== confirmPassword) {
      setError(t('setNewPassword.error.passwordMismatch'));
      return;
    }
    setLoading(true);
    try {
      await setNewPassword(email, session, newPassword);
      navigate('/');
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <form onSubmit={handleSubmit} className="form-container">
      <h2>{t('setNewPassword.title')}</h2>
      <TextInput
        label={t('setNewPassword.newPasswordLabel')}
        type="password"
        value={newPassword}
        onChange={e => setNewPasswordValue(e.target.value)}
        required
      />
      <TextInput
        label={t('setNewPassword.confirmPasswordLabel')}
        type="password"
        value={confirmPassword}
        onChange={e => setConfirmPassword(e.target.value)}
        required
      />
      <Button type="submit" loading={loading}>{t('setNewPassword.button')}</Button>
      {error && <div className="auth-error">{error}</div>}
      <div className="auth-links">
        <Link to="/signin" className="auth-link">{t('setNewPassword.cancelLink')}</Link>
      </div>
    </form>
  );
};

export default SetNewPasswordPage; 