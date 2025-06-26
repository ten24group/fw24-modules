import React, { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { signUp, SignUpResponse } from '../../services/api';
import TextInput from '../ui/TextInput';
import Button from '../ui/Button';
import { useTranslation } from 'react-i18next';

const SignUpPage: React.FC = () => {
  const [username, setUsername] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const navigate = useNavigate();
  const { t } = useTranslation();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    try {
      const response = await signUp({ username, email, password });
      if (response.UserConfirmed === false || response.session) {
        navigate('/confirm-signup', { state: { username: username || email } });
      } else {
        navigate('/signin');
      }
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <form onSubmit={handleSubmit}>
      <h2>{t('signUp.title')}</h2>
      <TextInput label={t('signUp.usernameLabel')} value={username} onChange={e => setUsername(e.target.value)} placeholder="Username" />
      <TextInput label={t('signUp.emailLabel')} type="email" value={email} onChange={e => setEmail(e.target.value)} placeholder="Email" />
      <TextInput label={t('signUp.passwordLabel')} type="password" value={password} onChange={e => setPassword(e.target.value)} placeholder="Password" />
      <Button type="submit" loading={loading}>{t('signUp.button')}</Button>
      {error && <div className="auth-error">{error}</div>}
      <div className="auth-links">
        <Link to="/signin" className="auth-link">{t('signUp.backLink')}</Link>
      </div>
    </form>
  );
};

export default SignUpPage; 