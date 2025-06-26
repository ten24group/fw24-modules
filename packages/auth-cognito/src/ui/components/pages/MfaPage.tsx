import React, { useState } from 'react';
import { useNavigate, useLocation, Link } from 'react-router-dom';
import { respondToOtpChallenge, SignInResponse } from '../../services/api';
import TextInput from '../ui/TextInput';
import Button from '../ui/Button';

interface LocationState {
  username: string;
  session: string;
  challengeName: string;
  challengeParameters?: Record<string, string>;
}

const MfaPage: React.FC = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const state = location.state as LocationState;
  const { username, session } = state;
  const [code, setCode] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    try {
      const response = await respondToOtpChallenge(username, session, code);
      if ('IdToken' in response) {
        window.parent.dispatchEvent(new CustomEvent('auth:success', { detail: response as SignInResponse }));
      }
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <form onSubmit={handleSubmit}>
      <h2>Enter MFA Code</h2>
      <p>Please enter the code sent to your device.</p>
      <TextInput label="Code" value={code} onChange={e => setCode(e.target.value)} placeholder="MFA code" />
      <Button type="submit" loading={loading}>Submit</Button>
      {error && <div className="auth-error">{error}</div>}
      <div className="auth-links">
        <Link to="/signin" className="auth-link">Cancel</Link>
      </div>
    </form>
  );
};

export default MfaPage; 