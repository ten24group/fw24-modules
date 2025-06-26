import React, { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { forgotPassword } from '../../services/api';
import TextInput from '../ui/TextInput';
import Button from '../ui/Button';

const ForgotPasswordPage: React.FC = () => {
  const navigate = useNavigate();
  const [identifier, setIdentifier] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    try {
      await forgotPassword(identifier);
      navigate('/confirm-forgot', { state: { username: identifier } });
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <form onSubmit={handleSubmit}>
      <h2>Forgot Password</h2>
      <TextInput label="Username or Email" value={identifier} onChange={e => setIdentifier(e.target.value)} placeholder="Username or Email" />
      <Button type="submit" loading={loading}>Send Code</Button>
      {error && <div className="auth-error">{error}</div>}
      <div className="auth-links">
        <Link to="/signin" className="auth-link">Back to Sign In</Link>
      </div>
    </form>
  );
};

export default ForgotPasswordPage; 