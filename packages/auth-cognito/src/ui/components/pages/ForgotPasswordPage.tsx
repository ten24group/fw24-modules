import React, { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { forgotPassword } from '../../services/api';
import TextInput from '../ui/TextInput';
import Button from '../ui/Button';
import { useTranslation } from 'react-i18next';

const ForgotPasswordPage: React.FC = () => {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const [email, setEmail] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    try {
      await forgotPassword(email);
      navigate('/confirm-forgot', { state: { email } });
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <form onSubmit={handleSubmit}>
      <h2>{t('forgotPassword.title')}</h2>
      <TextInput
        label={t('forgotPassword.emailLabel')}
        type="email"
        value={email}
        onChange={e => setEmail(e.target.value)}
        placeholder={t('forgotPassword.prompt')}
        required
      />
      <Button type="submit" loading={loading}>{t('forgotPassword.button')}</Button>
      {error && <div className="auth-error">{error}</div>}
      <div className="auth-links">
        <Link to="/signin" className="auth-link">{t('forgotPassword.backToSignInLink')}</Link>
      </div>
    </form>
  );
};

export default ForgotPasswordPage; 