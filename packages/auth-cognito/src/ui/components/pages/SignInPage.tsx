import React, { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { signIn, SignInResponse, Challenge, socialSignIn } from '../../services/api';
import TextInput from '../ui/TextInput';
import Button from '../ui/Button';
import config from '../../config.json';

const SignInPage: React.FC = () => {
  const [identifier, setIdentifier] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const navigate = useNavigate();
  const features = (config as any).features || {};

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    try {
      const response = await signIn({ username: identifier, password });
      if ('challengeName' in response) {
        // pass username and challenge data via navigation state for MFA
        const challenge = response as Challenge;
        navigate('/mfa', {
          state: {
            username: identifier,
            session: challenge.session,
            challengeName: challenge.challengeName,
            challengeParameters: challenge.challengeParameters,
          },
        });
      } else {
        // successful login
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
      <h2>Sign In</h2>
      <TextInput label="Username or Email" value={identifier} onChange={e => setIdentifier(e.target.value)} placeholder="Username or Email" />
      <TextInput label="Password" type="password" value={password} onChange={e => setPassword(e.target.value)} placeholder="Password" />
      {features.social?.enabled && (
        <div style={{ margin: '1rem 0' }}>
          {(features.social.providers || []).map((provider: string) => (
            <Button key={provider} type="button" onClick={() => socialSignIn(provider)}>
              {`Sign in with ${provider}`}
            </Button>
          ))}
        </div>
      )}
      <Button type="submit" loading={loading}>Sign In</Button>
      {error && <div className="auth-error">{error}</div>}
      <div className="auth-links">
        {features.signUp && <Link to="/signup" className="auth-link">Sign Up</Link>}
        {features.signUp && features.forgotPassword && ' | '}
        {features.forgotPassword && <Link to="/forgot-password" className="auth-link">Forgot Password</Link>}
      </div>
    </form>
  );
};

export default SignInPage; 