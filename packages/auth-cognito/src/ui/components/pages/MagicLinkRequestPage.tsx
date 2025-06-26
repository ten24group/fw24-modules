import React, { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { sendMagicLink } from '../../services/api';
import TextInput from '../ui/TextInput';
import Button from '../ui/Button';

const MagicLinkRequestPage: React.FC = () => {
  const [email, setEmail] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [isSent, setIsSent] = useState(false);
  const { t } = useTranslation();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    try {
      await sendMagicLink(email);
      setIsSent(true);
    } catch (err: any) {
      setError(err.message || t('errors.generic'));
    } finally {
      setLoading(false);
    }
  };

  if (isSent) {
    return (
      <div>
        <h2>{t('magicLinkRequest.title')}</h2>
        <p>A sign-in link has been sent to {email}. Please check your inbox.</p>
      </div>
    );
  }

  return (
    <form onSubmit={handleSubmit}>
      <h2>{t('magicLinkRequest.title')}</h2>
      <p>{t('magicLinkRequest.prompt')}</p>
      <TextInput
        label={t('magicLinkRequest.emailLabel')}
        type="email"
        value={email}
        onChange={(e) => setEmail(e.target.value)}
        placeholder="your@email.com"
        required
      />
      <Button type="submit" loading={loading}>{t('magicLinkRequest.button')}</Button>
      {error && <div className="auth-error">{error}</div>}
    </form>
  );
};

export default MagicLinkRequestPage; 