import React, { useEffect, useState } from 'react';
import { useSearchParams, useNavigate } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { verifyMagicLink, Tokens, SignInResponse } from '../../services/api';

const MagicLinkConfirmPage: React.FC = () => {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const [error, setError] = useState<string | null>(null);
  const { t } = useTranslation();

  useEffect(() => {
    const session = searchParams.get('session');
    const code = searchParams.get('code');
    const username = searchParams.get('username');

    if (!session || !code || !username) {
      setError('Magic link is missing required parameters.');
      return;
    }

    verifyMagicLink(username, session, code)
      .then((response: SignInResponse) => {
        if ('IdToken' in response) {
          console.log('Magic link sign-in successful');
          navigate('/');
        } else {
          setError(t('errors.unexpectedChallenge'));
        }
      })
      .catch((err: any) => {
        setError(err.message || t('errors.generic'));
      });
  }, [searchParams, t, navigate]);

  return (
    <div className="form-container">
      <h2>{t('magicLinkConfirm.title')}</h2>
      {error ? (
        <p className="error-message">{error}</p>
      ) : (
        <p>{t('magicLinkConfirm.prompt')}</p>
      )}
    </div>
  );
};

export default MagicLinkConfirmPage; 