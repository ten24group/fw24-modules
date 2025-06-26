import React, { useState, useEffect } from 'react';
import { useLocation, useNavigate, Link } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { selectMfaMethod, respondToMfaChallenge, Challenge, SignInResponse } from '../../services/api';
import TextInput from '../ui/TextInput';
import Button from '../ui/Button';

// @ts-ignore: using JSON import for runtime-injected config
import config from '../../config.json';

interface LocationState {
  username: string;
  session: string;
  challengeName?: string; // This can be SELECT_MFA_TYPE or a specific MFA challenge
}

type MfaMethod = 'SMS_MFA' | 'SOFTWARE_TOKEN_MFA';

const MfaPage: React.FC = () => {
    const navigate = useNavigate();
    const location = useLocation();
    const { t } = useTranslation();

    const [state, setSessionState] = useState<LocationState>(location.state as LocationState);
    const [code, setCode] = useState('');
    const [error, setError] = useState<string | null>(null);
    const [loading, setLoading] = useState(false);

    const isSelectMfa = state.challengeName === 'SELECT_MFA_TYPE';
    const availableMethods: MfaMethod[] = (config.features?.mfa?.methods || []) as MfaMethod[];

    const handleMethodSelect = async (method: MfaMethod) => {
        setError(null);
        setLoading(true);
        try {
            // Call API to inform Cognito of the selected MFA method
            const newChallenge = await selectMfaMethod(state.username, state.session, method);
            // Update session state with the new challenge details (e.g., SMS_MFA)
            setSessionState({
                ...state,
                challengeName: newChallenge.challengeName,
            });
        } catch (err: any) {
            setError(err.message);
        } finally {
            setLoading(false);
        }
    };

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        if (!state.challengeName || state.challengeName === 'SELECT_MFA_TYPE') {
            setError("MFA method not selected.");
            return;
        }
        setError(null);
        setLoading(true);
        try {
            const response = await respondToMfaChallenge(
                state.username,
                state.session,
                code,
                state.challengeName as MfaMethod // We now have the specific MFA type
            );
            
            if ('IdToken' in response) {
                console.log('MFA successful');
                navigate('/');
            } else {
                // This shouldn't happen in a normal flow, but handle it
                setError('An unexpected challenge was returned.');
                const newChallenge = response as Challenge;
                setSessionState({
                    ...state,
                    challengeName: newChallenge.challengeName,
                    session: newChallenge.session,
                });
            }
        } catch (err: any) {
            setError(err.message);
        } finally {
            setLoading(false);
        }
    };

    if (isSelectMfa) {
        return (
            <div className="form-container">
                <h2>{t('mfaSelect.title')}</h2>
                <p>{t('mfaSelect.prompt')}</p>
                {error && <p className="error-message">{error}</p>}
                {availableMethods.map(method => (
                    <Button key={method} onClick={() => handleMethodSelect(method as MfaMethod)} disabled={loading}>
                        {t(`mfaSelect.${method.toLowerCase()}`)}
                    </Button>
                ))}
            </div>
        );
    }

    return (
        <div className="form-container">
            <form onSubmit={handleSubmit}>
                <h2>{t('mfa.title')}</h2>
                <p>{t('mfa.prompt', { method: state.challengeName })}</p>
                {error && <p className="error-message">{error}</p>}
                <TextInput
                    label={t('mfa.codeLabel')}
                    value={code}
                    onChange={e => setCode(e.target.value)}
                    required
                />
                <Button type="submit" disabled={loading}>
                    {loading ? t('signIn.loading') : t('mfa.submitButton')}
                </Button>
                <div className="links">
                    <Link to="/signin">{t('mfa.cancelLink')}</Link>
                </div>
            </form>
        </div>
    );
};

export default MfaPage; 