import React, { useState } from 'react';
import { useNavigate, useLocation, Link } from 'react-router-dom';
import { confirmSignUp } from '../../services/api';
import TextInput from '../ui/TextInput';
import Button from '../ui/Button';

interface LocationState {
  username: string;
}

const ConfirmSignUpPage: React.FC = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const state = location.state as LocationState;
  const username = state?.username || '';
  const [code, setCode] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    try {
      await confirmSignUp(username, code);
      navigate('/signin');
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <form onSubmit={handleSubmit}>
      <h2>Confirm Sign Up</h2>
      <p>Enter the verification code sent to your email.</p>
      <TextInput label="Code" value={code} onChange={e => setCode(e.target.value)} placeholder="Verification code" />
      <Button type="submit" loading={loading}>Confirm</Button>
      {error && <div className="auth-error">{error}</div>}
      <div className="auth-links">
        <Link to="/signup" className="auth-link">Back to Sign Up</Link>{' | '}
        <Link to="/signin" className="auth-link">Back to Sign In</Link>
      </div>
    </form>
  );
};

export default ConfirmSignUpPage; 