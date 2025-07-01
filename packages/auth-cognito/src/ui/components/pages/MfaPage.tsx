import React, { useState, useEffect } from 'react';
import { useLocation, useNavigate, Link } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { selectMfaMethod, respondToMfaChallenge, Challenge, SignInResponse } from '../../services/api';
import { getUIConfig } from '../../runtime-config';
import type { UIConfig } from '../../types';
import { UIMfaMethod, CognitoMfaChallenge, UIMfaToCognitoMfaChallenge } from '../../../const';
import TextInput from '../ui/TextInput';
import Button from '../ui/Button';

// Type for MFA methods from UI features (always present due to defaults)
type UIFeatureMfaMethod = UIMfaMethod;

interface LocationState {
  email: string;
  session: string;
  challengeName?: string; // This can be SELECT_MFA_TYPE or a specific MFA challenge
}

const MfaPage: React.FC = () => {
    const navigate = useNavigate();
    const location = useLocation();
    const { t } = useTranslation();

    const [state, setSessionState] = useState<LocationState>(location.state as LocationState);
    const [code, setCode] = useState('');
    const [error, setError] = useState<string | null>(null);
    const [loading, setLoading] = useState(false);

    const isSelectMfa = state.challengeName === CognitoMfaChallenge.SELECT_MFA_TYPE;
    // UI feature methods are guaranteed by the deployed config defaults
    const availableMethods: UIFeatureMfaMethod[] = getUIConfig().features!.mfa!.methods as UIFeatureMfaMethod[];

    const handleMethodSelect = async (method: UIFeatureMfaMethod) => {
        setError(null);
        setLoading(true);
        try {
            // Map UI method to Cognito challenge name via shared constants
            const challengeName = UIMfaToCognitoMfaChallenge[method];
            const newChallenge = await selectMfaMethod(state.email, state.session, challengeName);
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
            const mfaType = state.challengeName! as
              | CognitoMfaChallenge.SMS_MFA
              | CognitoMfaChallenge.SOFTWARE_TOKEN_MFA;
            const response = await respondToMfaChallenge(
                state.email,
                state.session,
                code,
                mfaType
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
                    <Button key={method} onClick={() => handleMethodSelect(method)} disabled={loading}>
                        {t(`mfaSelect.${method.toLowerCase()}Button`)}
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
                    {loading ? t('signIn.loading') : t('mfa.button')}
                </Button>
                <div className="auth-links">
                    <Link to="/signin" className="auth-link">{t('mfa.cancelLink')}</Link>
                </div>
            </form>
        </div>
    );
};

export default MfaPage; 