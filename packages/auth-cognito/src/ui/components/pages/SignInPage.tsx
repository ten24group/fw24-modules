import React, { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { signIn, initiateSocialSignIn, Challenge, SignInResponse } from '../../services/api';
import TextInput from '../ui/TextInput';
import Button from '../ui/Button';
import { getUIConfig } from '../../runtime-config';
import { useTranslation } from 'react-i18next';
import { STORAGE_KEYS } from '../../../const';
import { emitEvent, Events } from '../../services/event-bus';

const SignInPage: React.FC = () => {
    const { t } = useTranslation();
    const navigate = useNavigate();
    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');
    const [error, setError] = useState<string | null>(null);
    const [loading, setLoading] = useState(false);

    const features = getUIConfig().features || {};

    const handleSignIn = async (e: React.FormEvent) => {
        e.preventDefault();
        setError(null);
        setLoading(true);

        try {
            const result = await signIn({
                username: email,
                password,
            });

            if ('challengeName' in result) {
                const challenge = result as Challenge;
                if (challenge.challengeName === 'NEW_PASSWORD_REQUIRED') {
                    navigate('/set-new-password', { state: { session: challenge.session, email } });
                } else {
                    navigate('/mfa', { state: { session: challenge.session, email, challengeName: challenge.challengeName } });
                }
            } else {
                console.log('Login successful');
                emitEvent(Events.LoginSuccess, result);
                navigate('/');
            }
        } catch (err: any) {
            setError(err.message);
            emitEvent(Events.LoginFailure, { message: err.message });
        } finally {
            setLoading(false);
        }
    };

    const handleSocialSignIn = (provider: string) => {
        sessionStorage.setItem(STORAGE_KEYS.oauthProvider, provider);
        const redirectUri = window.location.origin + (features.social?.callbackPath || '/oauth/callback');
        initiateSocialSignIn(provider, redirectUri);
    };

    return (
        <div className="form-container">
            <h2>{t('signIn.title')}</h2>
            {error && <p className="error-message">{error}</p>}
            <form onSubmit={handleSignIn}>
                <TextInput
                    label={t('signIn.emailLabel')}
                    type="email"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
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
                    {loading ? t('signIn.loading') : t('signIn.button')}
                </Button>
            </form>
            <div className="auth-links">
                {features.forgotPassword?.enabled && <Link to="/forgot-password" className="auth-link">{t('signIn.forgotPasswordLink')}</Link>}
                {features.signUp?.enabled && <Link to="/signup" className="auth-link">{t('signIn.signUpLink')}</Link>}
            </div>

            {features.social?.enabled && (
                <div className="social-logins">
                    <p>{t('signIn.or')}</p>
                    {(features.social.providers || []).map((p: any) => (
                         <Button key={p.id} onClick={() => handleSocialSignIn(p.id)}>
                           {t('social.signInWith', { provider: p.id })}
                         </Button>
                    ))}
                </div>
            )}
        </div>
    );
};

export default SignInPage; 