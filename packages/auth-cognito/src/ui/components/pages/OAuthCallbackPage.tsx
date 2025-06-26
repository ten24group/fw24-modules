import React, { useEffect, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { exchangeCode } from '../../services/oauth';
import { useTranslation } from 'react-i18next';
import { Tokens } from '../../services/api';

const OAuthCallbackPage: React.FC = () => {
  const [searchParams] = useSearchParams();
  const [error, setError] = useState<string | null>(null);
  const { t } = useTranslation();

  useEffect(() => {
    const code = searchParams.get('code');
    if (!code) {
      setError('Authorization code missing from callback URL.');
      return;
    }

    exchangeCode(code)
      .then((tokens: Tokens) => {
        window.parent.dispatchEvent(new CustomEvent('auth:success', { detail: tokens }));
      })
      .catch((err: any) => {
        setError(err.message || t('errors.tokenExchangeFailed'));
      });
  }, [searchParams, t]);

  return (
    <div>
      <h2>{t('oauthCallback.title')}</h2>
      {error ? (
        <div className="auth-error">{error}</div>
      ) : (
        <p>{t('oauthCallback.prompt')}</p>
      )}
    </div>
  );
};

export default OAuthCallbackPage; 