import React, { useEffect, useState } from 'react';
import { useSearchParams, useNavigate } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { completeSocialSignIn } from '../../services/api';
import { STORAGE_KEYS } from '../../../const';

const OAuthCallbackPage: React.FC = () => {
    const [searchParams] = useSearchParams();
    const navigate = useNavigate();
    const { t } = useTranslation();
    const [error, setError] = useState<string | null>(null);

    useEffect(() => {
        const code = searchParams.get('code');
        // The provider might be stored in session/local storage or passed in state
        // For this example, we assume it's recoverable or we use a default
        const provider = sessionStorage.getItem(STORAGE_KEYS.oauthProvider) || 'Google'; // Example recovery
        const redirectUri = window.location.origin + (window.location.pathname);

        if (!code) {
            setError(t('oauthCallback.missingCode'));
            return;
        }

        const handleSignInCompletion = async () => {
            try {
                const response = await completeSocialSignIn(provider, code, redirectUri);
                if ('IdToken' in response) {
                    console.log('Social sign-in successful');
                    navigate('/');
                } else {
                    setError(t('oauthCallback.unexpectedChallenge'));
                }
            } catch (err: any) {
                setError(err.message || t('oauthCallback.tokenExchangeFailed'));
            } finally {
                sessionStorage.removeItem(STORAGE_KEYS.oauthProvider); // Clean up
            }
        };

        handleSignInCompletion();
    }, [searchParams, navigate, t]);

    // Also need to update the SignInPage to save the provider to session storage before redirect
    // For now, this component is fixed to call the right API.

    return (
        <div className="form-container">
            <h2>{t('oauthCallback.title')}</h2>
            {error ? (
                <p className="error-message">{error}</p>
            ) : (
                <p>{t('oauthCallback.prompt')}</p>
            )}
        </div>
    );
};

export default OAuthCallbackPage; 