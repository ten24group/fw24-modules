import React, { useEffect, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { verifyMagicLink, Tokens } from '../../services/api';

const MagicLinkConfirmPage: React.FC = () => {
  const [searchParams] = useSearchParams();
  const [error, setError] = useState<string | null>(null);
  const { t } = useTranslation();

  useEffect(() => {
    const session = searchParams.get('session');
    const code = searchParams.get('code');

    if (!session || !code) {
      setError('Magic link is missing required parameters.');
      return;
    }

    verifyMagicLink(session, code)
      .then((tokens: Tokens) => {
        window.parent.dispatchEvent(new CustomEvent('auth:success', { detail: tokens }));
      })
      .catch((err: any) => {
        setError(err.message || t('errors.generic'));
      });
  }, [searchParams, t]);

  return (
    <div>
      <h2>{t('magicLinkConfirm.title')}</h2>
      {error ? (
        <div className="auth-error">{error}</div>
      ) : (
        <p>{t('magicLinkConfirm.prompt')}</p>
      )}
    </div>
  );
};

export default MagicLinkConfirmPage; 