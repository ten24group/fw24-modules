import React, { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { signIn, initiateSocialSignIn, Challenge, SignInResponse } from '../../services/api';
import TextInput from '../ui/TextInput';
import Button from '../ui/Button';
// @ts-ignore: using JSON import for runtime-injected config
import config from '../../config.json';
import { useTranslation } from 'react-i18next';

const SignInPage: React.FC = () => {
    const { t } = useTranslation();
    const navigate = useNavigate();
    const [identifier, setIdentifier] = useState('');
    const [password, setPassword] = useState('');
    const [error, setError] = useState<string | null>(null);
    const [loading, setLoading] = useState(false);

    const features = (config as any).features || {};

    const handleSignIn = async (e: React.FormEvent) => {
        e.preventDefault();
        setError(null);
        setLoading(true);

        try {
            const result = await signIn({
                username: identifier,
                password: password,
            });

            if ('challengeName' in result) {
                const challenge = result as Challenge;
                if (challenge.challengeName === 'NEW_PASSWORD_REQUIRED') {
                    navigate('/set-new-password', { state: { session: challenge.session, username: identifier } });
                } else {
                    navigate('/mfa', { state: { session: challenge.session, username: identifier, challengeName: challenge.challengeName } });
                }
            } else {
                console.log('Login successful');
                navigate('/');
            }
        } catch (err: any) {
            setError(err.message);
        } finally {
            setLoading(false);
        }
    };

    const handleSocialSignIn = (provider: string) => {
        sessionStorage.setItem('oauth_provider', provider);
        const redirectUri = window.location.origin + (features.social?.callbackPath || '/oauth/callback');
        initiateSocialSignIn(provider, redirectUri);
    };

    return (
        <div className="form-container">
            <h2>{t('signIn.title')}</h2>
            {error && <p className="error-message">{error}</p>}
            <form onSubmit={handleSignIn}>
                <TextInput
                    label={t('signIn.identifierLabel')}
                    type="text"
                    value={identifier}
                    onChange={(e) => setIdentifier(e.target.value)}
                    required
                />
                <TextInput
                    label={t('signIn.passwordLabel')}
                    type="password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    required
                />
                <Button type="submit" disabled={loading}>
                    {loading ? t('signIn.loading') : t('signIn.submitButton')}
                </Button>
            </form>
            <div className="links">
                {features.forgotPassword?.enabled && <Link to="/forgot-password">{t('signIn.forgotPasswordLink')}</Link>}
                {features.signUp?.enabled && <Link to="/signup">{t('signIn.signUpLink')}</Link>}
            </div>

            {features.social?.enabled && (
                <div className="social-logins">
                    <p>{t('signIn.socialLoginsTitle')}</p>
                    {(features.social.providers || []).map((p: any) => (
                         <Button key={p.provider} onClick={() => handleSocialSignIn(p.provider)}>
                           {t('signIn.signInWith', { provider: p.provider })}
                         </Button>
                    ))}
                </div>
            )}
        </div>
    );
};

export default SignInPage; 